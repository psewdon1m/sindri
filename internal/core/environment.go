package core

import (
	"os"
	"path/filepath"
	"runtime"
)

type Environment struct {
	Version         string
	ProtocolVersion string
	BuildID         string
	DataDir         string
	LogDir          string
	ConfigDir       string
	HostRoot        string
}

func NewEnvironment(version string, protocolVersion string, buildID string) Environment {
	dataDir := os.Getenv("SINDRI_DATA_DIR")
	logDir := os.Getenv("SINDRI_LOG_DIR")
	configDir := os.Getenv("SINDRI_CONFIG_DIR")
	hostRoot := os.Getenv("SINDRI_HOST_ROOT")
	defaults := defaultDirs()
	if dataDir == "" {
		dataDir = defaults.DataDir
	}
	if logDir == "" {
		logDir = defaults.LogDir
	}
	if configDir == "" {
		configDir = defaults.ConfigDir
	}
	if hostRoot == "" {
		hostRoot = string(filepath.Separator)
	}
	return Environment{
		Version:         version,
		ProtocolVersion: protocolVersion,
		BuildID:         buildID,
		DataDir:         dataDir,
		LogDir:          logDir,
		ConfigDir:       configDir,
		HostRoot:        filepath.Clean(hostRoot),
	}
}

type defaultDirectorySet struct {
	DataDir   string
	LogDir    string
	ConfigDir string
}

func defaultDirs() defaultDirectorySet {
	if runtime.GOOS == "linux" && os.Geteuid() == 0 {
		return defaultDirectorySet{
			DataDir:   string(filepath.Separator) + filepath.Join("var", "lib", "sindri"),
			LogDir:    string(filepath.Separator) + filepath.Join("var", "log", "sindri"),
			ConfigDir: string(filepath.Separator) + filepath.Join("etc", "sindri"),
		}
	}
	wd, err := os.Getwd()
	if err != nil {
		wd = "."
	}
	base := filepath.Join(wd, ".sindri")
	return defaultDirectorySet{
		DataDir:   filepath.Join(base, "lib"),
		LogDir:    filepath.Join(base, "log"),
		ConfigDir: filepath.Join(base, "etc"),
	}
}
