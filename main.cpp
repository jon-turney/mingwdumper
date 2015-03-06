#include <assert.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdint.h>

#include <map>


#define printhex(description, value) printf("%s: %#x\n", description, value)
#define printptr(value) printf("p:%p\n", value)

struct PeHeader {
    uint32_t mMagic; // PE\0\0 or 0x00004550
    uint16_t mMachine;
    uint16_t mNumberOfSections;
    uint32_t mTimeDateStamp;
    uint32_t mPointerToSymbolTable;
    uint32_t mNumberOfSymbols;
    uint16_t mSizeOfOptionalHeader;
    uint16_t mCharacteristics;
};

struct PeOptionalHeader {
    uint16_t mMagic; // 0x010b - PE32, 0x020b - PE32+ (64 bit)
    uint8_t  mMajorLinkerVersion;
    uint8_t  mMinorLinkerVersion;
    uint32_t mSizeOfCode;
    uint32_t mSizeOfInitializedData;
    uint32_t mSizeOfUninitializedData;
    uint32_t mAddressOfEntryPoint;
    uint32_t mBaseOfCode;
    uint32_t mBaseOfData;
    uint32_t mImageBase;
    uint32_t mSectionAlignment;
    uint32_t mFileAlignment;
    uint16_t mMajorOperatingSystemVersion;
    uint16_t mMinorOperatingSystemVersion;
    uint16_t mMajorImageVersion;
    uint16_t mMinorImageVersion;
    uint16_t mMajorSubsystemVersion;
    uint16_t mMinorSubsystemVersion;
    uint32_t mWin32VersionValue;
    uint32_t mSizeOfImage;
    uint32_t mSizeOfHeaders;
    uint32_t mCheckSum;
    uint16_t mSubsystem;
    uint16_t mDllCharacteristics;
    uint32_t mSizeOfStackReserve;
    uint32_t mSizeOfStackCommit;
    uint32_t mSizeOfHeapReserve;
    uint32_t mSizeOfHeapCommit;
    uint32_t mLoaderFlags;
    uint32_t mNumberOfRvaAndSizes;
};

#define IMAGE_SIZEOF_SHORT_NAME 8

struct IMAGE_SECTION_HEADER {
  char  Name[IMAGE_SIZEOF_SHORT_NAME];
  union {
    uint32_t PhysicalAddress;
    uint32_t VirtualSize;
  } ;
  uint32_t VirtualAddress;
  uint32_t SizeOfRawData;
  uint32_t PointerToRawData;
  uint32_t PointerToRelocations;
  uint32_t PointerToLinenumbers;
  uint16_t NumberOfRelocations;
  uint16_t NumberOfLinenumbers;
  uint32_t Characteristics;
};

struct __attribute__ ((__packed__))  PeSymbol
{
    union {
        char     n_name[8];  /* Symbol Name */
        struct {
            uint32_t n_first4bytes;
            uint32_t n_second4bytes;
        };
    };

    uint32_t n_value;    /* Value of Symbol */
    uint16_t n_scnum;    /* Section Number */
    uint16_t n_type;     /* Symbol Type */
    uint8_t  n_sclass;   /* Storage Class */
    uint8_t  n_numaux;   /* Auxiliary Count */
};

int main(int argc, char** argv)
{
    char* filename = argv[1];

    // code from breakpad
    int obj_fd = open(filename, O_RDONLY);
    if (obj_fd < 0) {
        fprintf(stderr, "Failed to open PE file '%s': %s\n",
                filename, strerror(errno));
        return -1;
    }

    struct stat st;
    if (fstat(obj_fd, &st) != 0 && st.st_size <= 0) {
        fprintf(stderr, "Unable to fstat PE file '%s': %s\n",
                filename, strerror(errno));
        return -1;
    }

    void* obj_base = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, obj_fd, 0);
    printhex("obj_base", obj_base);

    // offset 0x3c - find offset to PE signature
    int32_t* peOffsetPtr = (int32_t*) ( (int32_t*) obj_base + 60/4);
    printhex("signature offset", *peOffsetPtr);
    if (*peOffsetPtr > st.st_size)
      printf("invalid pe signature offset\n");

    // pe header
    PeHeader* peHeader = (PeHeader*) ((uint32_t*)obj_base+((*peOffsetPtr)/4));
    printhex("PeHeader Address", peHeader);
    printhex("mmagic", peHeader->mMagic);

    if (peHeader->mMagic != 0x00004550)
      printf("invalid pe signature\n");

    // optional pe header
    PeOptionalHeader* peOptionalHeader = (PeOptionalHeader*) ( (int32_t*) peHeader + 6);;
    printhex("pe header optional", peOptionalHeader);

    printhex("mmagic optional", peOptionalHeader->mMagic);

    printhex("image base", peOptionalHeader->mImageBase);

    uint64_t peOptionalHeaderOffset = (uint64_t) peOptionalHeader - (uint64_t) obj_base + 1;
    printhex("peOptionalHeader offset",  peOptionalHeaderOffset);
    printhex("peOptionalHeader + SizeOfOptionalHeader", peOptionalHeaderOffset + peHeader->mSizeOfOptionalHeader);

    int64_t sectionHeaderOffset = peOptionalHeaderOffset + peHeader->mSizeOfOptionalHeader;
    IMAGE_SECTION_HEADER* section_table = (IMAGE_SECTION_HEADER*) ((uint32_t*)obj_base+(sectionHeaderOffset/4));

    printf("sizeof(PeSymbol) = %d\n", sizeof(PeSymbol));
    printf("peHeader->mPointerToSymbolTable = %x\n", peHeader->mPointerToSymbolTable);
    printf("peHeader->mNumberOfSymbols = %d\n", peHeader->mNumberOfSymbols);

    // string table immediately follows symbol table
    uint32_t string_table_offset = peHeader->mPointerToSymbolTable + peHeader->mNumberOfSymbols*sizeof(PeSymbol);
    char *string_table = (char *)obj_base + string_table_offset;
    uint32_t string_table_length = *(uint32_t *)string_table;

    printf("string_table offset %x\n", string_table_offset);
    printf("string_table length %d\n", string_table_length);

    // string table index to pointer map
    std::map<unsigned int, char *> string_table_map;

    int i, offset;
    for (i = 0, offset = 4;
         offset < string_table_length;
         i++, offset += strlen(string_table+offset)+1)
      {
        //printf("%i: %s, length %d\n", i, string_table+offset, strlen(string_table+offset)+1);

        // stash pointer for later access via string table index
        string_table_map[i] = string_table+offset;
      }
    printf("%d strings\n", i-1);

    // dump out section table
    printf("Name                      VirtSize   VMA        RawSize    Offset     Flags\n");
    for (int s = 0; s < peHeader->mNumberOfSections; s++)
      {
        printf("%8.8s", section_table[s].Name);

        // long section name, look up in string table
        if (section_table[s].Name[0] == '/')
          {
            int offset = atoi(section_table[s].Name+1);

            if (offset > string_table_length)
              printf(" offset exceeds string table length");
            else
              printf(" %-16s ", string_table + offset);
          }
        else
          {
            printf("                  ");
          }

        printf("%08x   %08x   %08x   %08x   %08x\n",
               section_table[s].VirtualSize,
               section_table[s].VirtualAddress,
               section_table[s].SizeOfRawData,
               section_table[s].PointerToRawData,
               section_table[s].Characteristics);
      }

#if 0
    // dump out symbol table
    PeSymbol* symbols = (PeSymbol*) ((int32_t*) obj_base + (peHeader->mPointerToSymbolTable/4));
    for (unsigned int i = 0; i < peHeader->mNumberOfSymbols; i++)
    {
      printf("symbol name: ");

      if (symbols[i].n_first4bytes == 0)
        {
          offset = symbols[i].n_second4bytes;

            if (offset > string_table_length)
              printf("offset %#x exceeds string table length", offset);
            else
              printf("%s (offset %#x)", string_table + offset, offset);
        }
      else
        printf("%.8s", symbols[i].n_name);

      printf("\n");

      i = i + symbols[i].n_numaux;
    }
#endif
}
