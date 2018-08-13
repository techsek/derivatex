package internal

func ByteSlicesEqual(b1 *[]byte, b2 *[]byte) bool {
	if len(*b1) != len(*b2) {
		return false
	}
	for i := range *b1 {
		if (*b1)[i] != (*b2)[i] {
			return false
		}
	}
	return true
}

func ByteArrays32Equal(b1 *[32]byte, b2 *[32]byte) bool {
	for i := range *b1 {
		if (*b1)[i] != (*b2)[i] {
			return false
		}
	}
	return true
}
