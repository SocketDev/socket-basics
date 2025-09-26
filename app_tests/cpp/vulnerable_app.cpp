#include <iostream>
#include <string>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <memory>

// Hardcoded credentials
const std::string SECRET_PASSWORD = "admin123!@#";
const std::string API_KEY = "AKIAIOSFODNN7EXAMPLE";

class VulnerableUser {
public:
    char* name;
    char* email;
    
    VulnerableUser(const char* n, const char* e) {
        name = new char[strlen(n) + 1];
        email = new char[strlen(e) + 1];
        strcpy(name, n);  // Potential buffer overflow
        strcpy(email, e);
    }
    
    // Missing virtual destructor - potential issue in inheritance
    ~VulnerableUser() {
        delete[] name;
        delete[] email;
    }
    
    void displayInfo() {
        // Format string vulnerability potential
        std::cout << "User: " << name << ", Email: " << email << std::endl;
    }
};

void buffer_overflow_demo() {
    char buffer[64];
    std::string user_input;
    
    std::cout << "Enter your message: ";
    std::getline(std::cin, user_input);
    
    // Buffer overflow vulnerability
    strcpy(buffer, user_input.c_str());
    std::cout << "Message: " << buffer << std::endl;
}

void memory_management_issues() {
    // Memory leak
    int* leaked_ptr = new int[1000];
    *leaked_ptr = 42;
    // Never deleted
    
    // Double delete vulnerability
    int* ptr = new int(10);
    delete ptr;
    delete ptr;  // Double delete
    
    // Use after delete
    int* another_ptr = new int(20);
    delete another_ptr;
    std::cout << "Deleted value: " << *another_ptr << std::endl;  // Use after delete
}

void unsafe_vector_access() {
    std::vector<int> vec = {1, 2, 3, 4, 5};
    int index;
    
    std::cout << "Enter array index: ";
    std::cin >> index;
    
    // No bounds checking - potential out of bounds access
    std::cout << "Value at index " << index << ": " << vec[index] << std::endl;
}

void command_injection() {
    std::string filename;
    std::cout << "Enter filename to process: ";
    std::cin >> filename;
    
    // Command injection vulnerability
    std::string command = "cat " + filename;
    system(command.c_str());
}

class BaseClass {
public:
    virtual void process() {
        std::cout << "Base processing" << std::endl;
    }
    // Missing virtual destructor
};

class DerivedClass : public BaseClass {
private:
    char* data;
public:
    DerivedClass() {
        data = new char[100];
        strcpy(data, "Derived class data");
    }
    
    ~DerivedClass() {
        delete[] data;
    }
    
    void process() override {
        std::cout << "Derived processing: " << data << std::endl;
    }
};

void inheritance_vulnerability() {
    // Potential memory leak due to missing virtual destructor
    BaseClass* obj = new DerivedClass();
    obj->process();
    delete obj;  // May not call DerivedClass destructor properly
}

int main() {
    std::cout << "=== Vulnerable C++ Application ===" << std::endl;
    std::cout << "Using secret password: " << SECRET_PASSWORD << std::endl;
    
    std::cout << "\n1. Testing buffer overflow..." << std::endl;
    buffer_overflow_demo();
    
    std::cout << "\n2. Creating memory management issues..." << std::endl;
    memory_management_issues();
    
    std::cout << "\n3. Testing unsafe vector access..." << std::endl;
    unsafe_vector_access();
    
    std::cout << "\n4. Testing command injection..." << std::endl;
    command_injection();
    
    std::cout << "\n5. Testing inheritance vulnerability..." << std::endl;
    inheritance_vulnerability();
    
    std::cout << "\n6. Creating vulnerable user object..." << std::endl;
    VulnerableUser* user = new VulnerableUser("john_doe", "john@example.com");
    user->displayInfo();
    delete user;
    
    return 0;
}
