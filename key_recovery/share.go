package keyrecovery

type Share struct {
	x string
	y1 string
	y2 string
}

// Possibly when setting a value we could encode it in a specific format like hex or base64
// and when getting a value we could decode it from that format
// in that case we would to get and return []byte instead of string

func (s *Share) SetX(x string) {
	s.x = x
}

func (s *Share) SetSpending(y1 string) {
	s.y1 = y1
}

func (s *Share) SetViewing(y2 string) {
	s.y2 = y2
}

func (s *Share) GetX() string {
	return s.x
}

func (s *Share) GetSpending() string {
	return s.y1
}

func (s *Share) GetViewing() string {
	return s.y2
}


