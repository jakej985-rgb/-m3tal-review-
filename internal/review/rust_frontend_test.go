package review

import (
	"testing"
)

func TestRustSafetyRule_DetectsUnsafeWithoutRationale(t *testing.T) {
	src := `
pub fn allocate_raw() -> *mut u8 {
    unsafe {
        let layout = std::alloc::Layout::new::<u32>();
        std::alloc::alloc(layout)
    }
}
`
	diff := goDiff("src/allocator.rs", src)
	findings := (RustSafetyRule{}).Check(diff)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for undocumented unsafe, got %d", len(findings))
	}
	if findings[0].Rule != "rust-unsafe-safety-rationale" {
		t.Errorf("expected rule rust-unsafe-safety-rationale, got %s", findings[0].Rule)
	}
}

func TestRustSafetyRule_AllowsUnsafeWithSafetyComment(t *testing.T) {
	src := `
pub fn allocate_raw() -> *mut u8 {
    // SAFETY: Layout is non-zero size and properly aligned for u32.
    unsafe {
        let layout = std::alloc::Layout::new::<u32>();
        std::alloc::alloc(layout)
    }
}
`
	diff := goDiff("src/allocator.rs", src)
	findings := (RustSafetyRule{}).Check(diff)

	if len(findings) != 0 {
		t.Fatalf("expected 0 findings when // SAFETY: is present, got %d", len(findings))
	}
}

func TestRustFFIPanicRule_DetectsUncaughtPanicsInExternC(t *testing.T) {
	src := `
#[no_mangle]
pub extern "C" fn process_buffer(ptr: *const u8, len: usize) -> i32 {
    let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
    let val = std::str::from_utf8(slice).unwrap();
    val.len() as i32
}
`
	diff := goDiff("src/ffi.rs", src)
	findings := (RustFFIPanicRule{}).Check(diff)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for FFI panic unwind hazard, got %d", len(findings))
	}
	if findings[0].Rule != "rust-ffi-unwind" {
		t.Errorf("expected rule rust-ffi-unwind, got %s", findings[0].Rule)
	}
}

func TestRustFFIPanicRule_AllowsCatchUnwind(t *testing.T) {
	src := `
#[no_mangle]
pub extern "C" fn process_buffer(ptr: *const u8, len: usize) -> i32 {
    std::panic::catch_unwind(|| {
        let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
        let val = std::str::from_utf8(slice).unwrap();
        val.len() as i32
    }).unwrap_or(-1)
}
`
	diff := goDiff("src/ffi.rs", src)
	findings := (RustFFIPanicRule{}).Check(diff)

	if len(findings) != 0 {
		t.Fatalf("expected 0 findings when catch_unwind is used, got %d", len(findings))
	}
}

func TestRustAsyncLockRule_DetectsSyncLockAcrossAwait(t *testing.T) {
	src := `
pub async fn handle_request(state: Arc<std::sync::Mutex<State>>) -> Result<(), Error> {
    let mut guard = state.lock().unwrap();
    guard.counter += 1;
    tokio::time::sleep(Duration::from_millis(50)).await;
    Ok(())
}
`
	diff := goDiff("src/server.rs", src)
	findings := (RustAsyncLockRule{}).Check(diff)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for sync lock in async fn with await, got %d", len(findings))
	}
	if findings[0].Rule != "rust-async-lock-hazard" {
		t.Errorf("expected rule rust-async-lock-hazard, got %s", findings[0].Rule)
	}
}

func TestRustAsyncLockRule_AllowsTokioSyncMutex(t *testing.T) {
	src := `
pub async fn handle_request(state: Arc<tokio::sync::Mutex<State>>) -> Result<(), Error> {
    let mut guard = state.lock().await;
    guard.counter += 1;
    tokio::time::sleep(Duration::from_millis(50)).await;
    Ok(())
}
`
	diff := goDiff("src/server.rs", src)
	findings := (RustAsyncLockRule{}).Check(diff)

	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for tokio::sync::Mutex, got %d", len(findings))
	}
}

