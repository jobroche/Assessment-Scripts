import platform, os
from Assessment import *

def main():
    os = platform.system()
    print(os)
    if os == 'Windows':
        assessment = Windows()
    if os == 'Darwin':
        assessment = Mac()

if __name__ == "__main__":
    main()