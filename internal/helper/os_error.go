// SPDX-FileCopyrightText: 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package helper

import (
	"fmt"
	"os"
	"syscall"
)

func MarshalOSError(err error) error {
	if err == nil {
		return nil
	} else if pe, ok := err.(*os.PathError); ok {
		if errno, ok := pe.Err.(syscall.Errno); ok {
			return fmt.Errorf("%v", errno.Error())
		} else {
			return fmt.Errorf("%v", pe.Err.Error())
		}
	} else {
		return err
	}
}
