package internal

func errorsEqual(err error, expectedErr error) (bool, string) {
	if err == nil && expectedErr == nil {
		return true, ""
	}
	if err == nil && expectedErr != nil {
		return false, "Error is nil and not as the expected error " + expectedErr.Error()
	}
	if err != nil && expectedErr == nil {
		return false, "Error '" + err.Error() + "' is not nil as expected"
	}
	if err.Error() != expectedErr.Error() {
		return false, "Error '" + err.Error() + "' is not the expected error '" + expectedErr.Error() + "'"
	}
	return true, ""
}
