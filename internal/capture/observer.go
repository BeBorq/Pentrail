package capture

type shellObserver interface {
	Input([]byte, int64, bool)
	Output([]byte, int64, bool)
	Reset(off int64) // recording boundary at output offset off
	Close(off int64) // EOF: the shell ended, off = end of captured output
}
type noopObserver struct{}

func (noopObserver) Input([]byte, int64, bool)  {}
func (noopObserver) Output([]byte, int64, bool) {}
func (noopObserver) Reset(int64)                {}
func (noopObserver) Close(int64)                {}
