use std::process::Command;
use std::fs;
use std::io::{self, Write};
use std::ffi::CString;
use std::ptr;
use std::slice;
use std::collections::HashMap;
use std::alloc::{alloc, dealloc, Layout};

// Hardcoded secrets
const SECRET_KEY: &str = "rust_super_secret_2023";
const API_TOKEN: &str = "rs_1234567890abcdef";
const DB_PASSWORD: &str = "admin123!@#";

fn main() {
    println!("=== Vulnerable Rust Application ===");
    println!("Secret Key: {}", SECRET_KEY);
    
    println!("\n1. Testing unsafe memory operations...");
    unsafe_memory_operations();
    
    println!("\n2. Testing command injection...");
    command_injection_demo();
    
    println!("\n3. Testing path traversal...");
    path_traversal_demo();
    
    println!("\n4. Testing unsafe pointer operations...");
    unsafe_pointer_operations();
    
    println!("\n5. Testing buffer overflow in unsafe code...");
    unsafe_buffer_operations();
    
    println!("\n6. Testing information disclosure...");
    information_disclosure_demo();
    
    println!("\n7. Testing unsafe deserialization...");
    unsafe_deserialization_demo();
}

fn unsafe_memory_operations() {
    print!("Enter buffer size: ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let size: usize = input.trim().parse().unwrap_or(10);
    
    unsafe {
        // Memory leak - allocating without proper deallocation
        let layout = Layout::array::<i32>(size).unwrap();
        let leaked_ptr = alloc(layout) as *mut i32;
        if !leaked_ptr.is_null() {
            *leaked_ptr = 42;
            println!("Allocated {} bytes at {:p}", size * 4, leaked_ptr);
            // Intentionally not calling dealloc(leaked_ptr, layout)
        }
        
        // Use after free vulnerability
        let layout = Layout::array::<i32>(25).unwrap(); // 100 bytes / 4 = 25 i32s
        let ptr = alloc(layout) as *mut i32;
        if !ptr.is_null() {
            *ptr = 123;
            dealloc(ptr as *mut u8, layout);
            
            // Use after free - accessing freed memory
            println!("Value after free: {}", *ptr);  // Dangerous!
        }
        
        // Buffer overflow in unsafe code
        let layout = Layout::from_size_align(64, 1).unwrap();
        let buffer = alloc(layout) as *mut u8;
        if !buffer.is_null() {
            // Writing beyond allocated buffer
            for i in 0..100 {
                *buffer.offset(i) = 0x41;  // Potential buffer overflow
            }
            dealloc(buffer, layout);
        }
    }
}

fn command_injection_demo() {
    print!("Enter filename to process: ");
    io::stdout().flush().unwrap();
    let mut filename = String::new();
    io::stdin().read_line(&mut filename).unwrap();
    let filename = filename.trim();
    
    // Command injection vulnerability
    let command = format!("ls -la {}", filename);
    println!("Executing command: {}", command);
    
    match Command::new("sh").arg("-c").arg(&command).output() {
        Ok(output) => {
            println!("Command output: {}", String::from_utf8_lossy(&output.stdout));
        }
        Err(e) => println!("Command execution error: {}", e),
    }
}

fn path_traversal_demo() {
    print!("Enter file path to read: ");
    io::stdout().flush().unwrap();
    let mut file_path = String::new();
    io::stdin().read_line(&mut file_path).unwrap();
    let file_path = file_path.trim();
    
    // Path traversal vulnerability - no validation
    match fs::read_to_string(file_path) {
        Ok(content) => {
            let preview = if content.len() > 200 {
                &content[0..200]
            } else {
                &content
            };
            println!("File content: {}...", preview);
        }
        Err(e) => println!("File read error: {}", e),
    }
}

fn unsafe_pointer_operations() {
    unsafe {
        // Dangling pointer vulnerability
        let mut vec = vec![1, 2, 3, 4, 5];
        let ptr = vec.as_mut_ptr();
        
        // Drop the vector, making the pointer dangling
        drop(vec);
        
        // Use dangling pointer - undefined behavior
        println!("Dangling pointer value: {}", *ptr);
        
        // Null pointer dereference
        let _null_ptr: *const i32 = ptr::null();
        // This would crash the program
        // println!("Null pointer value: {}", *null_ptr);
        
        // Raw pointer arithmetic without bounds checking
        let array = [1, 2, 3, 4, 5];
        let ptr = array.as_ptr();
        
        // Accessing out of bounds
        for i in 0..10 {  // Array only has 5 elements
            let value = *ptr.offset(i);
            println!("Array[{}] = {}", i, value);
        }
    }
}

fn unsafe_buffer_operations() {
    print!("Enter data to copy: ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let input_bytes = input.trim().as_bytes();
    
    unsafe {
        // Fixed-size buffer that can overflow
        let buffer_size = 64;
        let layout = Layout::from_size_align(buffer_size, 1).unwrap();
        let buffer = alloc(layout) as *mut u8;
        
        if !buffer.is_null() {
            // Buffer overflow vulnerability - copying without size checking
            ptr::copy_nonoverlapping(
                input_bytes.as_ptr(),
                buffer,
                input_bytes.len(),  // Could be larger than buffer_size
            );
            
            // Create a slice from potentially overflowed buffer
            let slice = slice::from_raw_parts(buffer, std::cmp::min(input_bytes.len(), buffer_size));
            println!("Buffer content: {:?}", slice);
            
            dealloc(buffer, layout);
        }
    }
}

fn information_disclosure_demo() {
    // Information disclosure through error messages and logging
    let database_config = HashMap::from([
        ("host", "localhost"),
        ("user", "admin"),
        ("password", DB_PASSWORD),
        ("api_key", API_TOKEN),
    ]);
    
    println!("Database configuration: {:?}", database_config);
    
    // Simulating an error with sensitive information
    match simulate_database_connection() {
        Ok(_) => println!("Database connected successfully"),
        Err(e) => {
            println!("Database connection failed with full details: {}", e);
            println!("Connection string: host=localhost, user=admin, password={}", DB_PASSWORD);
            println!("API Token for debugging: {}", API_TOKEN);
        }
    }
}

fn simulate_database_connection() -> Result<(), String> {
    Err(format!("Connection failed: Invalid credentials for user 'admin' with password '{}'", DB_PASSWORD))
}

fn unsafe_deserialization_demo() {
    print!("Enter serialized data (as numbers separated by spaces): ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    
    // Unsafe deserialization - directly interpreting user input as memory
    let numbers: Vec<u8> = input
        .trim()
        .split_whitespace()
        .filter_map(|s| s.parse().ok())
        .collect();
    
    if !numbers.is_empty() {
        unsafe {
            // Unsafe: treating arbitrary bytes as a specific type
            let ptr = numbers.as_ptr() as *const usize;
            println!("Interpreted as usize: {}", *ptr);
            
            // Potential vulnerability: treating user data as function pointer
            let fn_ptr = numbers.as_ptr() as *const fn();
            println!("Function pointer address: {:p}", fn_ptr);
            // Note: Actually calling this would be extremely dangerous
        }
    }
}

// Unsafe global mutable state
static mut GLOBAL_COUNTER: i32 = 0;
static mut GLOBAL_BUFFER: [u8; 256] = [0; 256];

fn unsafe_global_state_demo() {
    unsafe {
        // Race condition vulnerability - accessing global mutable state
        GLOBAL_COUNTER += 1;
        println!("Global counter: {}", GLOBAL_COUNTER);
        
        // Unsafe modification of global buffer
        for i in 0..300 {  // Buffer overflow - writing beyond array bounds
            if i < GLOBAL_BUFFER.len() {
                GLOBAL_BUFFER[i] = (i % 256) as u8;
            }
        }
    }
}

// Vulnerable trait implementation
trait Executor {
    fn execute(&self, code: &str);
}

struct UnsafeExecutor;

impl Executor for UnsafeExecutor {
    fn execute(&self, code: &str) {
        // Extremely dangerous: executing arbitrary code
        println!("Executing: {}", code);
        
        // In a real scenario, this might use FFI to call system functions
        // or use other unsafe mechanisms to execute the code
        let c_string = CString::new(code).unwrap();
        let c_ptr = c_string.as_ptr();
        println!("Would execute C string at: {:p}", c_ptr);
    }
}

// Vulnerable smart pointer usage
fn vulnerable_smart_pointers() {
    use std::rc::Rc;
    use std::cell::RefCell;
    
    // Potential memory leak with reference cycles
    let shared_data = Rc::new(RefCell::new(vec![1, 2, 3, 4, 5]));
    let _another_ref = Rc::clone(&shared_data);
    
    // Simulating a reference cycle (would cause memory leak)
    println!("Shared data references: {}", Rc::strong_count(&shared_data));
    
    // Unsafe borrow checking bypass
    let borrowed = shared_data.borrow_mut();
    // This could panic if there are multiple borrows
    drop(borrowed);
}
