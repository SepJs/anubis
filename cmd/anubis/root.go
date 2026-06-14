package main

import (
	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "anubis",
	Short: "Anubis Security Scanner",
	Long:  `Anubis is an advanced indie security scanner for modern web applications.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Delegate the execution to the scan dispatcher defined in scan.go
		return dispatchScan()
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		// Log errors handled by cobra
	}
}

func init() {
	// Initialize CLI flags here
	rootCmd.PersistentFlags().StringVarP(&target, "target", "t", "", "Target URL")
	rootCmd.PersistentFlags().IntVarP(&level, "level", "l", 1, "Scan level (1-3)")
}