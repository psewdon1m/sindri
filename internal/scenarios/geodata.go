package scenarios

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"sindri/internal/adapters"
	"sindri/internal/core"
)

const (
	geoDataContainerDir    = "/usr/local/share/xray"
	geoDataSourceBaseURL   = "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release"
	geoDataDownloadTimeout = 10 * time.Minute
	geoDataDockerTimeout   = 2 * time.Minute
	geoDataMaxAssetBytes   = int64(256 * 1024 * 1024)
	geoDataMinFreeBytes    = uint64(512 * 1024 * 1024)
	geoDataBackupRetention = 3
)

var (
	geoDataNames         = []string{"geosite.dat", "geoip.dat"}
	geoDataSHA256        = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
	geoDataContainerName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`)
	geoDataBackupName    = regexp.MustCompile(`^\d{8}T\d{6}Z-(?:[a-f0-9]{8}|\d{14})$`)
	geoDataAssetLoader   = loadGeoDataAssets
	geoDataSteps         = []core.StepSpec{
		{ID: "precheck", Name: "Verify Docker and the selected container"},
		{ID: "download", Name: "Download the current geodata release"},
		{ID: "checksum", Name: "Verify release SHA-256 checksums"},
		{ID: "backup", Name: "Back up the installed geodata"},
		{ID: "replace", Name: "Replace geodata and restart the selected container"},
		{ID: "verify", Name: "Verify the container and installed files"},
	}
)

type geoDataAsset struct {
	Name   string
	Path   string
	SHA256 string
	Size   int64
}

type geoDataManifest struct {
	Schema      int                    `json:"schema"`
	CreatedAt   string                 `json:"created_at"`
	Container   string                 `json:"container"`
	Destination string                 `json:"destination"`
	Source      string                 `json:"source"`
	Files       []geoDataManifestAsset `json:"files"`
}

type geoDataManifestAsset struct {
	Name           string `json:"name"`
	PreviousSHA256 string `json:"previous_sha256"`
	NewSHA256      string `json:"new_sha256"`
	NewSize        int64  `json:"new_size"`
}

func geoGet(ctx core.Context, req core.Request, inputs map[string]interface{}) core.Result {
	container, ok := inputs["container"].(string)
	container = strings.TrimSpace(container)
	if !ok || !geoDataContainerName.MatchString(container) {
		return geoDataFailure("GEODATA_CONTAINER_NAME_INVALID", "a valid Docker container name is required", "precheck", core.ExitInvalidCommand)
	}
	if failure := requireLinuxRoot("GEODATA_PRECHECK_FAILED"); failure != nil {
		return *failure
	}
	if !adapters.CommandExists("docker") {
		return geoDataFailure("DOCKER_NOT_FOUND", "Docker is not installed", "precheck", core.ExitPrecheckFailed)
	}
	if err := os.MkdirAll(ctx.Env.DataDir, 0750); err != nil {
		return geoDataFailure("GEODATA_PRECHECK_FAILED", err.Error(), "precheck", core.ExitPrecheckFailed)
	}
	free, err := diskFreeBytes(ctx.Env.DataDir)
	if err != nil || free < geoDataMinFreeBytes {
		message := "at least 512 MB of free space is required"
		if err != nil {
			message = err.Error()
		}
		return geoDataFailure("GEODATA_DISK_SPACE_LOW", message, "precheck", core.ExitPrecheckFailed)
	}
	if run := geoDataDocker(ctx, "inspect", "--type", "container", "--format", "{{.State.Running}}", container); run.ExitCode != 0 {
		return geoDataFailure("GEODATA_CONTAINER_NOT_FOUND", commandResultMessage(run), "precheck", core.ExitPrecheckFailed)
	} else if strings.TrimSpace(run.Stdout) != "true" {
		return geoDataFailure("GEODATA_CONTAINER_NOT_RUNNING", "container "+container+" must be running before the update", "precheck", core.ExitPrecheckFailed)
	}

	workspace, err := os.MkdirTemp("", "sindri-geodata-*")
	if err != nil {
		return geoDataFailure("GEODATA_WORKSPACE_FAILED", err.Error(), "download", core.ExitGeneralFailure)
	}
	defer os.RemoveAll(workspace)

	assets, err := geoDataAssetLoader(ctx, filepath.Join(workspace, "release"))
	if err != nil {
		return geoDataFailure("GEODATA_DOWNLOAD_FAILED", err.Error(), "download", core.ExitVerificationFailed)
	}
	if err := validateGeoDataAssets(assets); err != nil {
		return geoDataFailure("GEODATA_RELEASE_INVALID", err.Error(), "checksum", core.ExitVerificationFailed)
	}
	if ctx.Log != nil {
		for _, asset := range assets {
			ctx.Log.Write("geodata_download file=%s size=%d sha256=%s", asset.Name, asset.Size, asset.SHA256)
		}
	}

	currentDir := filepath.Join(workspace, "current")
	if err := os.MkdirAll(currentDir, 0750); err != nil {
		return geoDataFailure("GEODATA_BACKUP_FAILED", err.Error(), "backup", core.ExitGeneralFailure)
	}
	current, copyResult, err := copyContainerGeoData(ctx, container, currentDir)
	if err != nil {
		if copyResult != nil {
			return geoDataCommandFailure("GEODATA_CURRENT_FILES_UNAVAILABLE", "backup", *copyResult)
		}
		return geoDataFailure("GEODATA_CURRENT_FILES_UNAVAILABLE", err.Error(), "backup", core.ExitPrecheckFailed)
	}
	if geoDataAssetsEqual(current, assets) {
		return success("Xray geodata is already up to date", false, geoDataResultData(container, "", current, assets, false))
	}

	backupDirectory, err := writeGeoDataBackup(ctx.Env, container, current, assets)
	if err != nil {
		return geoDataFailure("GEODATA_BACKUP_FAILED", err.Error(), "backup", core.ExitGeneralFailure)
	}
	if ctx.Log != nil {
		ctx.Log.Write("geodata_backup path=%s", backupDirectory)
	}

	stop := geoDataDocker(ctx, "stop", "--time", "30", container)
	if stop.ExitCode != 0 {
		start := geoDataDocker(ctx, "start", container)
		if start.ExitCode != 0 {
			return geoDataRollbackFailure(container, "GEODATA_STOP_FAILED", commandResultMessage(stop), backupDirectory, errors.New(commandResultMessage(start)))
		}
		if err := verifyGeoDataContainer(ctx, container); err != nil {
			return geoDataRollbackFailure(container, "GEODATA_STOP_FAILED", commandResultMessage(stop), backupDirectory, err)
		}
		return geoDataCommandFailure("GEODATA_STOP_FAILED", "replace", stop)
	}

	if err := installGeoDataAssets(ctx, container, assets); err != nil {
		return rollbackGeoData(ctx, container, "GEODATA_REPLACE_FAILED", err, backupDirectory, current)
	}
	if err := verifyContainerGeoData(ctx, container, assets, workspace); err != nil {
		return rollbackGeoData(ctx, container, "GEODATA_REPLACE_VERIFY_FAILED", err, backupDirectory, current)
	}
	if run := geoDataDocker(ctx, "start", container); run.ExitCode != 0 {
		return rollbackGeoData(ctx, container, "GEODATA_START_FAILED", errors.New(commandResultMessage(run)), backupDirectory, current)
	}
	if err := verifyGeoDataContainer(ctx, container); err != nil {
		return rollbackGeoData(ctx, container, "GEODATA_RUNTIME_VERIFY_FAILED", err, backupDirectory, current)
	}

	data := geoDataResultData(container, backupDirectory, current, assets, true)
	if err := pruneGeoDataBackups(ctx.Env, geoDataBackupRetention); err != nil {
		data["backup_cleanup_warning"] = err.Error()
		if ctx.Log != nil {
			ctx.Log.Write("geodata_backup_cleanup warning=%s", err)
		}
	}
	return success("Xray geodata updated and "+container+" restarted", true, data)
}

func loadGeoDataAssets(ctx context.Context, directory string) ([]geoDataAsset, error) {
	if err := os.MkdirAll(directory, 0750); err != nil {
		return nil, err
	}
	client := &http.Client{
		Timeout: geoDataDownloadTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			if req.URL.Scheme != "https" {
				return errors.New("geodata download redirected away from HTTPS")
			}
			return nil
		},
	}
	return downloadGeoDataAssets(ctx, client, geoDataSourceBaseURL, directory)
}

func downloadGeoDataAssets(ctx context.Context, client *http.Client, baseURL, directory string) ([]geoDataAsset, error) {
	before, err := fetchGeoDataChecksums(ctx, client, baseURL)
	if err != nil {
		return nil, fmt.Errorf("fetch release checksums: %w", err)
	}

	type result struct {
		asset geoDataAsset
		err   error
	}
	downloadContext, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan result, len(geoDataNames))
	for _, name := range geoDataNames {
		name := name
		go func() {
			asset, downloadErr := downloadGeoDataAsset(downloadContext, client, baseURL, directory, name, before[name])
			results <- result{asset: asset, err: downloadErr}
		}()
	}
	byName := make(map[string]geoDataAsset, len(geoDataNames))
	for range geoDataNames {
		item := <-results
		if item.err != nil {
			cancel()
			return nil, item.err
		}
		byName[item.asset.Name] = item.asset
	}

	after, err := fetchGeoDataChecksums(ctx, client, baseURL)
	if err != nil {
		return nil, fmt.Errorf("recheck release checksums: %w", err)
	}
	assets := make([]geoDataAsset, 0, len(geoDataNames))
	for _, name := range geoDataNames {
		if before[name] != after[name] {
			return nil, fmt.Errorf("release changed while downloading %s; retry the command", name)
		}
		assets = append(assets, byName[name])
	}
	return assets, nil
}

func fetchGeoDataChecksums(ctx context.Context, client *http.Client, baseURL string) (map[string]string, error) {
	type result struct {
		name string
		hash string
		err  error
	}
	results := make(chan result, len(geoDataNames))
	for _, name := range geoDataNames {
		name := name
		go func() {
			body, err := downloadGeoDataText(ctx, client, strings.TrimRight(baseURL, "/")+"/"+name+".sha256sum")
			hash := ""
			if err == nil {
				hash, err = parseGeoDataChecksum(body, name)
			}
			results <- result{name: name, hash: hash, err: err}
		}()
	}
	checksums := make(map[string]string, len(geoDataNames))
	for range geoDataNames {
		item := <-results
		if item.err != nil {
			return nil, fmt.Errorf("%s: %w", item.name, item.err)
		}
		checksums[item.name] = item.hash
	}
	return checksums, nil
}

func downloadGeoDataText(ctx context.Context, client *http.Client, url string) (string, error) {
	response, err := doGeoDataRequest(ctx, client, url)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	if err != nil {
		return "", err
	}
	if len(body) > 4096 {
		return "", errors.New("checksum response is too large")
	}
	return string(body), nil
}

func downloadGeoDataAsset(ctx context.Context, client *http.Client, baseURL, directory, name, expected string) (geoDataAsset, error) {
	path := filepath.Join(directory, name)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		return geoDataAsset{}, err
	}
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(path)
		}
	}()

	response, err := doGeoDataRequest(ctx, client, strings.TrimRight(baseURL, "/")+"/"+name)
	if err != nil {
		return geoDataAsset{}, err
	}
	defer response.Body.Close()
	hasher := sha256.New()
	size, err := io.Copy(io.MultiWriter(file, hasher), io.LimitReader(response.Body, geoDataMaxAssetBytes+1))
	if err != nil {
		return geoDataAsset{}, err
	}
	if size > geoDataMaxAssetBytes {
		return geoDataAsset{}, fmt.Errorf("%s exceeds the %d-byte safety limit", name, geoDataMaxAssetBytes)
	}
	if err := file.Sync(); err != nil {
		return geoDataAsset{}, err
	}
	if err := file.Close(); err != nil {
		return geoDataAsset{}, err
	}
	actual := hex.EncodeToString(hasher.Sum(nil))
	if actual != expected {
		return geoDataAsset{}, fmt.Errorf("%s checksum mismatch: expected %s, got %s", name, expected, actual)
	}
	remove = false
	return geoDataAsset{Name: name, Path: path, SHA256: actual, Size: size}, nil
}

func doGeoDataRequest(ctx context.Context, client *http.Client, url string) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", "sindri-geodata/1")
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		_ = response.Body.Close()
		return nil, fmt.Errorf("%s returned HTTP %d", url, response.StatusCode)
	}
	return response, nil
}

func parseGeoDataChecksum(body, name string) (string, error) {
	fields := strings.Fields(body)
	if len(fields) == 0 || !geoDataSHA256.MatchString(fields[0]) {
		return "", errors.New("invalid SHA-256 checksum response")
	}
	if len(fields) > 1 && strings.TrimPrefix(fields[1], "*") != name {
		return "", fmt.Errorf("checksum is for %q, not %q", fields[1], name)
	}
	return strings.ToLower(fields[0]), nil
}

func validateGeoDataAssets(assets []geoDataAsset) error {
	if len(assets) != len(geoDataNames) {
		return fmt.Errorf("expected %d geodata files, got %d", len(geoDataNames), len(assets))
	}
	byName := make(map[string]geoDataAsset, len(assets))
	for _, asset := range assets {
		if asset.Path == "" || asset.Size <= 0 || !geoDataSHA256.MatchString(asset.SHA256) {
			return fmt.Errorf("invalid downloaded asset %q", asset.Name)
		}
		if _, duplicate := byName[asset.Name]; duplicate {
			return fmt.Errorf("duplicate downloaded asset %q", asset.Name)
		}
		byName[asset.Name] = asset
	}
	for _, name := range geoDataNames {
		if _, ok := byName[name]; !ok {
			return fmt.Errorf("downloaded release is missing %s", name)
		}
	}
	return nil
}

func copyContainerGeoData(ctx core.Context, container, directory string) ([]geoDataAsset, *adapters.CommandResult, error) {
	assets := make([]geoDataAsset, 0, len(geoDataNames))
	for _, name := range geoDataNames {
		path := filepath.Join(directory, name)
		run := geoDataDocker(ctx, "cp", container+":"+geoDataContainerDir+"/"+name, path)
		if run.ExitCode != 0 {
			return nil, &run, errors.New(commandResultMessage(run))
		}
		hash, size, err := hashGeoDataFile(path)
		if err != nil {
			return nil, nil, fmt.Errorf("inspect installed %s: %w", name, err)
		}
		assets = append(assets, geoDataAsset{Name: name, Path: path, SHA256: hash, Size: size})
	}
	return assets, nil, nil
}

func hashGeoDataFile(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	hasher := sha256.New()
	size, err := io.Copy(hasher, io.LimitReader(file, geoDataMaxAssetBytes+1))
	if err != nil {
		return "", 0, err
	}
	if size == 0 {
		return "", 0, errors.New("file is empty")
	}
	if size > geoDataMaxAssetBytes {
		return "", 0, fmt.Errorf("file exceeds the %d-byte safety limit", geoDataMaxAssetBytes)
	}
	return hex.EncodeToString(hasher.Sum(nil)), size, nil
}

func geoDataAssetsEqual(first, second []geoDataAsset) bool {
	if len(first) != len(second) {
		return false
	}
	hashes := make(map[string]string, len(first))
	for _, asset := range first {
		hashes[asset.Name] = asset.SHA256
	}
	for _, asset := range second {
		if hashes[asset.Name] != asset.SHA256 {
			return false
		}
	}
	return true
}

func writeGeoDataBackup(env core.Environment, container string, current, replacement []geoDataAsset) (string, error) {
	backupDirectory := filepath.Join(env.DataDir, "backups", "geodata", time.Now().UTC().Format("20060102T150405Z")+"-"+core.NewShortID())
	if err := os.MkdirAll(backupDirectory, 0750); err != nil {
		return "", err
	}
	completed := false
	defer func() {
		if !completed {
			_ = os.RemoveAll(backupDirectory)
		}
	}()
	newByName := make(map[string]geoDataAsset, len(replacement))
	for _, asset := range replacement {
		newByName[asset.Name] = asset
	}
	manifest := geoDataManifest{
		Schema:      1,
		CreatedAt:   time.Now().UTC().Format(time.RFC3339),
		Container:   container,
		Destination: geoDataContainerDir,
		Source:      geoDataSourceBaseURL,
		Files:       make([]geoDataManifestAsset, 0, len(current)),
	}
	for _, asset := range current {
		if err := copyGeoDataFile(asset.Path, filepath.Join(backupDirectory, asset.Name), 0640); err != nil {
			return "", err
		}
		updated := newByName[asset.Name]
		manifest.Files = append(manifest.Files, geoDataManifestAsset{
			Name: asset.Name, PreviousSHA256: asset.SHA256, NewSHA256: updated.SHA256, NewSize: updated.Size,
		})
	}
	body, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return "", err
	}
	if err := atomicWrite(filepath.Join(backupDirectory, "manifest.json"), append(body, '\n'), 0640); err != nil {
		return "", err
	}
	completed = true
	return backupDirectory, nil
}

func copyGeoDataFile(source, destination string, mode os.FileMode) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	remove := true
	defer func() {
		_ = output.Close()
		if remove {
			_ = os.Remove(destination)
		}
	}()
	if _, err := io.Copy(output, input); err != nil {
		return err
	}
	if err := output.Sync(); err != nil {
		return err
	}
	if err := output.Close(); err != nil {
		return err
	}
	remove = false
	return nil
}

func pruneGeoDataBackups(env core.Environment, retain int) error {
	if retain < 1 {
		return errors.New("at least one geodata backup must be retained")
	}
	directory := filepath.Join(env.DataDir, "backups", "geodata")
	entries, err := os.ReadDir(directory)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	backups := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !geoDataBackupName.MatchString(entry.Name()) {
			continue
		}
		path := filepath.Join(directory, entry.Name())
		if info, err := os.Stat(filepath.Join(path, "manifest.json")); err != nil || !info.Mode().IsRegular() {
			continue
		}
		backups = append(backups, path)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(backups)))
	for _, path := range backups[minimum(retain, len(backups)):] {
		if err := os.RemoveAll(path); err != nil {
			return fmt.Errorf("remove old backup %s: %w", path, err)
		}
	}
	return nil
}

func minimum(first, second int) int {
	if first < second {
		return first
	}
	return second
}

func installGeoDataAssets(ctx core.Context, container string, assets []geoDataAsset) error {
	for _, asset := range assets {
		destination := container + ":" + geoDataContainerDir + "/" + asset.Name
		run := geoDataDocker(ctx, "cp", asset.Path, destination)
		if run.ExitCode != 0 {
			return errors.New(commandResultMessage(run))
		}
	}
	return nil
}

func verifyContainerGeoData(ctx core.Context, container string, expected []geoDataAsset, workspace string) error {
	verificationDirectory := filepath.Join(workspace, "verify-"+core.NewShortID())
	if err := os.MkdirAll(verificationDirectory, 0750); err != nil {
		return err
	}
	actual, run, err := copyContainerGeoData(ctx, container, verificationDirectory)
	if err != nil {
		if run != nil {
			return errors.New(commandResultMessage(*run))
		}
		return err
	}
	if !geoDataAssetsEqual(actual, expected) {
		return errors.New("installed files do not match the verified release checksums")
	}
	return nil
}

func verifyGeoDataContainer(ctx core.Context, container string) error {
	for attempt := 0; attempt < 10; attempt++ {
		run := geoDataDocker(ctx, "inspect", "--type", "container", "--format", "{{.State.Running}}", container)
		if run.ExitCode == 0 && strings.TrimSpace(run.Stdout) == "true" {
			for _, name := range geoDataNames {
				fileCheck := geoDataDocker(ctx, "exec", container, "test", "-s", geoDataContainerDir+"/"+name)
				if fileCheck.ExitCode != 0 {
					return fmt.Errorf("%s is not readable in the running container: %s", name, commandResultMessage(fileCheck))
				}
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return errors.New("container " + container + " did not reach the running state")
}

func rollbackGeoData(ctx core.Context, container, code string, cause error, backupDirectory string, previous []geoDataAsset) core.Result {
	errorsFound := make([]string, 0)
	if run := geoDataDocker(ctx, "stop", "--time", "30", container); run.ExitCode != 0 {
		errorsFound = append(errorsFound, "stop: "+commandResultMessage(run))
	}
	for _, asset := range previous {
		source := filepath.Join(backupDirectory, asset.Name)
		destination := container + ":" + geoDataContainerDir + "/" + asset.Name
		if run := geoDataDocker(ctx, "cp", source, destination); run.ExitCode != 0 {
			errorsFound = append(errorsFound, "restore "+asset.Name+": "+commandResultMessage(run))
		}
	}
	verificationDirectory, tempErr := os.MkdirTemp("", "sindri-geodata-rollback-*")
	if tempErr != nil {
		errorsFound = append(errorsFound, "verify restore: "+tempErr.Error())
	} else {
		defer os.RemoveAll(verificationDirectory)
		if err := verifyContainerGeoData(ctx, container, previous, verificationDirectory); err != nil {
			errorsFound = append(errorsFound, "verify restore: "+err.Error())
		}
	}
	if run := geoDataDocker(ctx, "start", container); run.ExitCode != 0 {
		errorsFound = append(errorsFound, "start: "+commandResultMessage(run))
	} else if err := verifyGeoDataContainer(ctx, container); err != nil {
		errorsFound = append(errorsFound, "verify: "+err.Error())
	}
	if len(errorsFound) > 0 {
		return geoDataRollbackFailure(container, code, cause.Error(), backupDirectory, errors.New(strings.Join(errorsFound, "; ")))
	}
	return core.Result{
		Status:  core.StatusFailed,
		Changed: false,
		Message: "Xray geodata update failed; the previous files were restored",
		Data: map[string]interface{}{
			"backup": backupDirectory, "container": container, "rolled_back": true,
		},
		Error:    &core.ErrorInfo{Code: code, Message: cause.Error()},
		Steps:    failedSteps(geoDataSteps, "replace"),
		ExitCode: core.ExitVerificationFailed,
	}
}

func geoDataRollbackFailure(container, code, cause, backupDirectory string, rollbackErr error) core.Result {
	return core.Result{
		Status:  core.StatusPartial,
		Changed: true,
		Message: "Xray geodata update failed and automatic rollback was incomplete",
		Data: map[string]interface{}{
			"backup": backupDirectory, "container": container, "rolled_back": false,
		},
		Error: &core.ErrorInfo{Code: code, Message: cause + "; rollback failed: " + rollbackErr.Error()},
		Steps: failedSteps(geoDataSteps, "replace"), ExitCode: core.ExitPartialSuccess,
	}
}

func geoDataResultData(container, backup string, previous, current []geoDataAsset, restarted bool) map[string]interface{} {
	previousHashes := make(map[string]string, len(previous))
	currentHashes := make(map[string]string, len(current))
	for _, asset := range previous {
		previousHashes[asset.Name] = asset.SHA256
	}
	for _, asset := range current {
		currentHashes[asset.Name] = asset.SHA256
	}
	data := map[string]interface{}{
		"container": container, "destination": geoDataContainerDir, "source": geoDataSourceBaseURL,
		"previous_sha256": previousHashes, "sha256": currentHashes, "restarted": restarted,
	}
	if backup != "" {
		data["backup"] = backup
	}
	return data
}

func geoDataFailure(code, message, step string, exitCode int) core.Result {
	return core.Result{
		Status: core.StatusFailed, Message: "Xray geodata update failed",
		Error: &core.ErrorInfo{Code: code, Message: message}, Steps: failedSteps(geoDataSteps, step), ExitCode: exitCode,
	}
}

func geoDataCommandFailure(code, step string, run adapters.CommandResult) core.Result {
	exitCode := core.ExitGeneralFailure
	if run.TimedOut {
		exitCode = core.ExitTimeout
	}
	return geoDataFailure(code, commandResultMessage(run), step, exitCode)
}

func commandResultMessage(run adapters.CommandResult) string {
	message := strings.TrimSpace(run.Stderr)
	if message == "" {
		message = strings.TrimSpace(run.Stdout)
	}
	if message == "" {
		message = fmt.Sprintf("%s exited with code %d", strings.Join(run.Command, " "), run.ExitCode)
	}
	return message
}

func geoDataDocker(ctx context.Context, args ...string) adapters.CommandResult {
	return adapters.RunWithTimeout(ctx, geoDataDockerTimeout, "docker", args...)
}
