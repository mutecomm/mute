all:
	go install -v github.com/mutecomm/mute/cmd/mutegenerate
	go generate -v github.com/mutecomm/mute/release
	go install -v github.com/mutecomm/mute/cmd/...
