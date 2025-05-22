import os
import ctypes
import datetime
import sys
from ctypes import *
from ctypes.wintypes import *

# Define constants
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x80
INVALID_HANDLE_VALUE = -1
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002

# File Device Types
FILE_DEVICE_UNKNOWN = 0x00000022

# Method Codes
METHOD_BUFFERED = 0
METHOD_IN_DIRECT = 1
METHOD_OUT_DIRECT = 2
METHOD_NEITHER = 3

# Access Codes
FILE_ANY_ACCESS = 0
FILE_READ_DATA = 0x0001
FILE_WRITE_DATA = 0x0002

# Define control code macro
def CTL_CODE(DeviceType, Function, Method, Access):
    return ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method)

# Define the exact IOCTL code from tdriver.h
IOCTL_REGISTRY_ANALYZER_BASE = 0x8000
IOCTL_EXPORT_REGISTRY_FEATURES_CSV = CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTL_REGISTRY_ANALYZER_BASE + 1, METHOD_BUFFERED, FILE_ANY_ACCESS)

# Error constants
ERROR_INSUFFICIENT_BUFFER = 122

# Handle wrapper to avoid ctypes conversion issues
class SafeHandle:
    def __init__(self, handle_value):
        self.handle = handle_value
        
    def close(self):
        if self.handle is not None and self.handle != INVALID_HANDLE_VALUE:
            try:
                CloseHandle = ctypes.windll.kernel32.CloseHandle
                CloseHandle(self.handle)
                result = True
            except Exception as e:
                print(f"Error closing handle: {e}")
                result = False
            self.handle = None
            return result
        return True
        
    @property
    def value(self):
        return self.handle

class RegistryDataExporter:
    def __init__(self):
        self.device_handle = None
        # Use the correct device path from tdriver.cpp
        self.device_paths = [
            "\\\\.\\RegistryAnalyzer",        # Correct path found in tdriver.cpp
            "\\\\.\\gp-driver-registry3004",   # Service name as backup
            "\\\\.\\ObCallbackTest"           # Added based on project name
        ]
        self.output_dir = os.path.dirname(os.path.abspath(__file__))
        self.output_file = None
        # Increased default buffer size to accommodate unlimited feature vectors
        self.default_buffer_size = 4 * 1024 * 1024  # 4MB default
        
    def open_device(self):
        """Attempts to open a handle to the driver device."""
        # Clean up old handle if exists
        if self.device_handle is not None:
            self.close_device()
        
        # Try each device path
        for device_path in self.device_paths:
            print(f"Attempting to open device: {device_path}")
            
            try:
                # Open device using WinAPI
                handle = ctypes.windll.kernel32.CreateFileW(
                    device_path,
                    GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    None,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    None
                )
                
                # Check if handle is valid
                if handle != INVALID_HANDLE_VALUE:
                    self.device_handle = SafeHandle(handle)
                    print(f"Successfully opened device: {device_path}")
                    return True
                else:
                    error_code = ctypes.GetLastError()
                    print(f"Failed to open device. Error code: {error_code}")
            except Exception as e:
                print(f"Exception trying to open {device_path}: {e}")
        
        print("Failed to open any device path")
        return False
    
    def close_device(self):
        """Closes the handle to the driver device."""
        if self.device_handle is not None:
            try:
                self.device_handle.close()
                print("Device handle closed")
            except Exception as e:
                print(f"Exception during close_device: {str(e)}")
            finally:
                self.device_handle = None
    
    def get_buffer_size(self):
        """Queries the driver for required buffer size."""
        if self.device_handle is None:
            print("Invalid device handle")
            return None
            
        # Create a buffer to receive the required size (ULONG)
        initial_buffer_size = 16  # Increased from 8 to 16 bytes just to be safe
        size_buffer = (c_char * initial_buffer_size)()
        bytes_returned = DWORD(0)
        
        # Get device IO control function
        DeviceIoControl = ctypes.windll.kernel32.DeviceIoControl
        
        print(f"Querying CSV buffer size using IOCTL: 0x{IOCTL_EXPORT_REGISTRY_FEATURES_CSV:08X}")
        
        try:
            # Try to get the buffer size needed
            success = DeviceIoControl(
                self.device_handle.value,
                IOCTL_EXPORT_REGISTRY_FEATURES_CSV,
                None,
                0,
                byref(size_buffer),
                initial_buffer_size,
                byref(bytes_returned),
                None
            )
            
            if not success:
                error_code = ctypes.GetLastError()
                # If error is buffer too small, we should get the required size
                if error_code == ERROR_INSUFFICIENT_BUFFER:
                    # Parse required size from returned buffer
                    required_size = c_ulong.from_buffer_copy(size_buffer).value
                    print(f"Buffer too small. Required size: {required_size} bytes")
                    return required_size
                elif error_code == 0:
                    # Some versions of Windows return success=False but error=0, handle this case
                    required_size = c_ulong.from_buffer_copy(size_buffer).value
                    print(f"Required buffer size: {required_size} bytes")
                    return required_size
                else:
                    print(f"Failed to get buffer size. Error code: {error_code}")
                    return None
            else:
                # If success, get the size from the return buffer
                required_size = c_ulong.from_buffer_copy(size_buffer).value
                print(f"Required buffer size: {required_size} bytes")
                return required_size
        except Exception as e:
            print(f"Exception getting buffer size: {str(e)}")
            return None
    
    def export_registry_data_to_csv(self):
        """Exports registry data from the driver to a CSV file."""
        if self.device_handle is None:
            print("Invalid device handle")
            return False
        
        # Try to get the required buffer size
        required_size = self.get_buffer_size()
        
        # If we couldn't get a valid size, use a default
        if required_size is None or required_size == 0:
            required_size = self.default_buffer_size
            print(f"Using default buffer size: {required_size} bytes")
        else:
            # Add 20% extra space just to be safe with unlimited feature vectors
            required_size = int(required_size * 1.2)
            print(f"Adjusted buffer size to: {required_size} bytes (added 20% margin)")
        
        # Allocate buffer for CSV data
        try:
            # Use a larger buffer allocation to ensure we can handle all feature vectors
            max_attempts = 3
            success = False
            attempt = 1
            
            while not success and attempt <= max_attempts:
                try:
                    print(f"Attempt {attempt}: Allocating buffer of size {required_size} bytes")
                    csv_buffer = (c_char * required_size)()
                    bytes_returned = DWORD(0)
                    
                    # Get the actual CSV data
                    print(f"Requesting CSV data...")
                    DeviceIoControl = ctypes.windll.kernel32.DeviceIoControl
                    result = DeviceIoControl(
                        self.device_handle.value,
                        IOCTL_EXPORT_REGISTRY_FEATURES_CSV,
                        None,
                        0,
                        byref(csv_buffer),
                        required_size,
                        byref(bytes_returned),
                        None
                    )
                    
                    if not result:
                        error_code = ctypes.GetLastError()
                        if error_code == ERROR_INSUFFICIENT_BUFFER:
                            print(f"Buffer still too small. Increasing size...")
                            required_size *= 2  # Double the buffer size
                            attempt += 1
                            continue
                        else:
                            print(f"Failed to get CSV data. Error code: {error_code}")
                            return False
                    
                    success = True
                except MemoryError:
                    print(f"Memory allocation error with buffer size: {required_size}")
                    if required_size > 1024*1024*10:  # Don't try to allocate more than 10MB
                        print("Reached maximum reasonable buffer size")
                        return False
                    required_size = int(required_size * 0.75)  # Try a smaller buffer
                    attempt += 1
                except Exception as e:
                    print(f"Exception during CSV data retrieval: {str(e)}")
                    return False
            
            if not success:
                print(f"Failed to allocate appropriate buffer after {max_attempts} attempts")
                return False
            
            bytes_actually_returned = bytes_returned.value
            print(f"Successfully received {bytes_actually_returned} bytes of CSV data")
            
            # Check if any data was actually returned
            if bytes_actually_returned == 0:
                print("No data was returned from the driver (0 bytes)")
                return False
                
            # Create output directory if it doesn't exist
            if not os.path.exists(self.output_dir):
                os.makedirs(self.output_dir)
                
            # Write data to CSV file
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            output_filename = f"registry_data_{timestamp}.csv"
            output_path = os.path.join(self.output_dir, output_filename)
            
            with open(output_path, 'wb') as f:
                f.write(csv_buffer[:bytes_actually_returned])
            
            print(f"CSV data written to: {output_path}")
            self.output_file = output_path
            
            # Try to read header from the exported file to verify format
            try:
                with open(output_path, 'r', encoding='utf-8') as f:
                    header = f.readline().strip()
                    field_count = len(header.split(','))
                    print(f"CSV file contains {field_count} fields per row")
                    
                    # Count total rows to verify feature vector count
                    f.seek(0)
                    row_count = sum(1 for _ in f) - 1  # Subtract 1 for header
                    
                    print(f"CSV contains {row_count} feature vectors (rows)")
                    
                    # Expected field count for our updated format
                    expected_count = 38  # Updated count with new fields
                    if field_count != expected_count:
                        print(f"Warning: CSV header has {field_count} fields, expected {expected_count}")
                        print("This could indicate a mismatch between driver and exporter versions")
                        # Print the actual header for troubleshooting
                        print(f"Actual header: {header}")
                    else:
                        print("CSV format validation successful")
            except Exception as e:
                print(f"Note: Could not verify CSV format: {e}")
            
            return True
        except Exception as e:
            print(f"Exception exporting data: {str(e)}")
            traceback_info = traceback.format_exc() if 'traceback' in sys.modules else "Traceback not available"
            print(f"Detailed error information: {traceback_info}")
            return False

def main():
    print("Registry Data Exporter - Modified for Unlimited Feature Vectors")
    print("===========================================================")
    print("This tool exports registry activity data collected by the kernel driver.")
    print("All registry feature vectors will be exported without limits.")
    
    exporter = RegistryDataExporter()
    
    try:
        # Try to open the device
        if exporter.open_device():
            print("\nSuccessfully connected to driver. Exporting registry data...")
            if exporter.export_registry_data_to_csv():
                print(f"\nRegistry data successfully exported to: {exporter.output_file}")
                print("Export completed successfully.")
                print("\nNote: All feature vectors have been exported without limitation")
                print("as per the modified driver implementation.")
            else:
                print("\nFailed to export registry data from driver.")
                print("Possible causes:")
                print("1. Driver has not collected any registry data yet.")
                print("2. Driver is still in the process of collecting data.")
                print("3. Driver export functionality is not correctly implemented.")
                print("\nTry running some applications that access the registry")
                print("and then try exporting again.")
        else:
            print("\nFailed to connect to driver.")
            print("Please check the following:")
            print("1. Make sure the driver is installed and running.")
            print("2. Make sure you're running this tool as Administrator.")
            print("3. Verify that the correct device name is being used.")
            print("\nNo data was exported.")
    except Exception as e:
        print(f"\nUnexpected error: {str(e)}")
        
        # Add detailed traceback if available
        if 'traceback' in sys.modules:
            import traceback
            print("\nDetailed error information:")
            traceback.print_exc()
    finally:
        # Always close the device handle
        if exporter.device_handle is not None:
            exporter.close_device()

if __name__ == "__main__":
    # Import traceback conditionally to avoid errors if not available
    try:
        import traceback
    except ImportError:
        pass
    
    main()