package udp

type Message struct {
	Sender   string `json:"senderId"`
	Receiver string `json:"receiverId"`
	Content  string `json:"content"`
}
