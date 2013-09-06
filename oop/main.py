import platform, os
from Assessment import *

def main():
    os = platform.system()
    if os == 'Windows':
        assessment = Windows()

if __name__ == "__main__":
    main()