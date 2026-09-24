// SPDX-FileCopyrightText: 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

// Package landlock applies best-effort Linux Landlock restrictions through
// go-landlock. Existing file descriptors remain usable.
package landlock

import (
	"errors"
	"fmt"
	"log/slog"
	"syscall"
	"time"

	golandlock "github.com/landlock-lsm/go-landlock/landlock"
	llsyscall "github.com/landlock-lsm/go-landlock/landlock/syscall"
	"pxy.se/go/ssh-sign/pkg/cli"
)

const targetABI = 10

// signalScopeErrata is the Landlock erratum fixed by bit 1. go-landlock
// downgrades ABI 6 and newer to ABI 5 when the fix is not reported.
const signalScopeErrata = 1 << 1

var errUnsupported = errors.New("unsupported by this kernel")

// kernelABI returns the raw kernel ABI without go-landlock's errata downgrades.
// It can distinguish unavailable enforcement, but not the effective ABI.
func kernelABI() (int, error) {
	abi, err := llsyscall.LandlockGetABIVersion()
	if err == nil && abi >= 1 {
		return abi, nil
	}
	if err == nil {
		return 0, errUnsupported
	}
	if errors.Is(err, syscall.ENOSYS) || errors.Is(err, syscall.EOPNOTSUPP) ||
		errors.Is(err, syscall.EPERM) {
		return 0, errUnsupported
	}
	return 0, fmt.Errorf("failed querying the ABI version: %w", err)
}

type abiStatus struct {
	kernel    int
	adjusted  int
	effective int
}

// detectedABI mirrors the ABI cap, errata downgrade, and minimum in
// go-landlock v0.10.1. It is used only for reporting after go-landlock has
// applied the policy.
func detectedABI() (abiStatus, error) {
	kernel, err := kernelABI()
	if err != nil {
		return abiStatus{}, err
	}

	var errata int
	var errataErr error
	if kernel >= 6 {
		errata, errataErr = llsyscall.LandlockGetErrata()
	}
	return abiStatusFor(kernel, errata, errataErr), nil
}

func abiStatusFor(kernel, errata int, errataErr error) abiStatus {
	adjusted := adjustedABI(kernel, errata, errataErr)
	return abiStatus{
		kernel:    kernel,
		adjusted:  adjusted,
		effective: applyMinimumABI(adjusted),
	}
}

func adjustedABI(kernel, errata int, errataErr error) int {
	adjusted := kernel
	if kernel >= 6 && (errataErr != nil || errata&signalScopeErrata == 0) {
		adjusted = 5
	}
	return min(adjusted, targetABI)
}

func applyMinimumABI(adjusted int) int {
	if adjusted < minimumRequiredABI {
		return 0
	}
	return adjusted
}

// Restrict denies new filesystem access, execution, TCP and UDP networking,
// and access to external pathname and abstract unix sockets. Call it after
// opening required inputs. Unsupported or disabled Landlock is not an error.
func Restrict(log *slog.Logger) error {
	cli.Debug(log, cli.LevelDebug2, "landlock: configuring",
		"policy_abi", targetABI, "best_effort", true,
	)

	// Local timestamps need zone data before filesystem access is denied.
	_, _ = time.Now().Zone()

	if err := golandlock.V10.BestEffort().Restrict(); err != nil {
		return err
	}
	status, err := detectedABI()
	if err != nil {
		cli.Debug(log, cli.LevelDebug2, "landlock: ABI query failed", "error", err)
		cli.Debug(log, cli.LevelDebug1, "landlock: unavailable", "best_effort", true)
		return nil
	}
	if status.effective == 0 {
		cli.Debug(log, cli.LevelDebug2, "landlock: adjusted ABI below build minimum",
			"kernel_abi", status.kernel, "adjusted_abi", status.adjusted,
			"minimum_abi", minimumRequiredABI,
		)
		cli.Debug(log, cli.LevelDebug1, "landlock: unavailable", "best_effort", true)
		return nil
	}
	cli.Debug(log, cli.LevelDebug1, "landlock: enabled",
		"effective_abi", status.effective, "kernel_abi", status.kernel,
		"threads", "all", "best_effort", true,
	)
	return nil
}
