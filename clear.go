package main

func clearByteSlice(secretPtr *[]byte) {
	if secretPtr != nil {
		for i := range *secretPtr {
			(*secretPtr)[i] = byte(0)
			(*secretPtr)[i] = byte(1)
			(*secretPtr)[i] = byte(0)
		}
		*secretPtr = nil
		secretPtr = nil
	}
}

func clearByteArray32(secretPtr *[32]byte) {
	if secretPtr != nil {
		for i := range *secretPtr {
			(*secretPtr)[i] = byte(0)
			(*secretPtr)[i] = byte(1)
			(*secretPtr)[i] = byte(0)
		}
		secretPtr = nil
	}
}

func clearUint32(secretPtr *uint32) {
	if secretPtr != nil {
		*secretPtr = 0
		secretPtr = nil
	}
}

func clearAndTrim(secretPtr *[]byte, n int) {
	if n < 0 {
		n = 0
	}
	if L := len(*secretPtr); L < n {
		n = L
	}
	for i := 0; i < n; i++ {
		(*secretPtr)[i] = byte(0)
		(*secretPtr)[i] = byte(1)
		(*secretPtr)[i] = byte(0)
	}
	*secretPtr = (*secretPtr)[n:]
}
