[64 bits] 

;==================================================================================
;					Created by The Ghost In The Matrix
;==================================================================================

; But away that for Intel I need to do AMD and RISC-V 
; and about ARM I dont doing it because he is very dynamic and don't want low level guys to touch it 
; so I doing for Intel AMD and RISC-V and that for Intel 
; entry pointes length: 
; ==============================================================================
;  SYSTEM MANAGEMENT BIOS - REVERSE ENGINEERING & ISOLATION CORE
; ==============================================================================
; Structural alignment steps and strict table constraints for validation scanning
SMBIOS_EPS_SEARCH_STEP equ 16      ; Scanner jump interval in F0000h-FFFFFh ROM memory segment
SMBIOS_EPS_LEN_V2      equ 0x1F    ; Entry Point Structure total byte length for SMBIOS V2.x
SMBIOS_EPS_LEN_V3      equ 0x18    ; Entry Point Structure total byte length for modern V3.x

; Anchor Signatures for memory scanning alignment (Enforcing anti-spoofing verification)
SMBIOS_SIG_32        equ 0x5F4D535F  ; Little-endian string match for "_SM_" identifier block
SMBIOS_SIG_64        equ 0x5F534D5F  ; Little-endian string match for "_SM3_" modern 64-bit block

; --- SMBIOS 2.x (32-bit) Entry Point Structure Offsets ----------------------
EPS_32_SIGNATURE     equ 0x00        ; 4 Bytes: "_SM_" Anchor string window
EPS_32_CHECKSUM      equ 0x04        ; 1 Byte: Strict mathematical checksum over EPS block
EPS_32_LENGTH        equ 0x05        ; 1 Byte: Struct format size validator (Must equal 0x1F)
EPS_32_MAJOR_VER     equ 0x06        ; 1 Byte: Architectural major specification compliance
EPS_32_MINOR_VER     equ 0x07        ; 1 Byte: Architectural minor specification compliance
EPS_32_MAX_STRUCT    equ 0x08        ; 2 Bytes: Peak byte allocation size for any isolated structure
EPS_32_REVISION      equ 0x0A        ; 1 Byte: Internal layout revision byte matrix
EPS_32_FORMAT_AREA   equ 0x0B        ; 5 Bytes: Hardened reserved zone for internal firmware markers
EPS_32_DMI_SIG       equ 0x10        ; 5 Bytes: Legacy sub-anchor string identifier window ("_DMI_")
EPS_32_DMI_CHKSUM    equ 0x15        ; 1 Byte: Legacy sub-checksum validator tracking configuration
EPS_32_TABLE_LEN     equ 0x16        ; 2 Bytes: Aggregate byte runtime allocation size for data blocks
EPS_32_TABLE_ADDR    equ 0x18        ; 4 Bytes: Physical 32-bit direct memory address pointing to data tables
EPS_32_NUM_STRUCTS   equ 0x1C        ; 2 Bytes: Total available structure blocks assigned by firmware
EPS_32_BCD_REVISION  equ 0x1E        ; 1 Byte: Compliance release version encoded in BCD format

; --- SMBIOS 3.x (64-bit) Entry Point Structure Offsets (Modern Intel Layout) --
EPS_64_SIGNATURE     equ 0x00        ; 5 Bytes: "_SM3_" Long anchor string window
EPS_64_CHECKSUM      equ 0x05        ; 1 Byte: Strict mathematical checksum over V3 EPS block
EPS_64_LENGTH        equ 0x06        ; 1 Byte: Struct format size validator (Must equal 0x18)
EPS_64_MAJOR_VER     equ 0x07        ; 1 Byte: Architectural major spec tracker (Modern platforms)
EPS_64_MINOR_VER     equ 0x08        ; 1 Byte: Architectural minor spec tracker (Modern platforms)
EPS_64_DOC_REV       equ 0x09        ; 1 Byte: Developer manual documentation layout revision
EPS_64_REVISION      equ 0x0A        ; 1 Byte: Current EPS structure layout format revision
EPS_64_RESERVED      equ 0x0B        ; 1 Byte: Silicon alignment compliance buffer field
EPS_64_TABLE_MAX_LEN equ 0x0C        ; 4 Bytes: Maximum possible length variable for data segments
EPS_64_TABLE_ADDR    equ 0x10        ; 8 Bytes: Absolute physical 64-bit address window of actual data structures


; The tables of SMBIOS are dynamicly in the RAM and they can get poisened by the Rootkits from the operating system so I'm going to give you the 
; Signature of every single one of them and the structure. You gonna need to know how to find them, all tables are working the same offsets and everything 
; The Structure looks like this in every start of tables:
; offset 0x00 got the Type of the table
; offset 0x01 got the length of the table
; offset 0x02 got the Handle of the table
; if type is 0 he is BIOS INFORMATION, wether he is type 5 then he MEMORY CONTROLLER
; I tried not to make any mistakes if you see any mistake tell me I'm going to fix it
; Have fun at building it! if you are hardcore assembler like me goodluck soldier


; --- CORE STRUCTURE HEADER OFFSETS (Common to ALL SMBIOS tables) -------------
STRUCT_HEADER_TYPE   equ 0x00    ; 1 Byte: Specifies the type of structure (e.g., Type 0, Type 1)
STRUCT_HEADER_LENGTH equ 0x01    ; 1 Byte: Length of the formatted area in bytes
STRUCT_HEADER_HANDLE equ 0x02    ; 2 Bytes: Unique 16-bit identifier for the structure

; --- CRITICAL HARDWARE STRUCTURE TYPES (The ones Rootkits try to poison) ------
SMBIOS_TYPE_BIOS     equ 0       ; Type 0: BIOS Information (Vendor, Version, Release Date)
SMBIOS_TYPE_SYSTEM   equ 1       ; Type 1: System Information (Manufacturer, Product Name, UUID)
SMBIOS_TYPE_BASEBRD  equ 2       ; Type 2: Baseboard/Motherboard Information
SMBIOS_TYPE_CHASSIS  equ 3       ; Type 3: System Enclosure/Chassis Matrix
SMBIOS_TYPE_PROC     equ 4       ; Type 4: Processor Information (Family, Core Count, Frequency)
SMBIOS_TYPE_MEMDEV   equ 17      ; Type 17: Memory Device Details (RAM size, Speed, Factor)

; --- GENERIC FIELD OFFSETS FOR CORES DETECTION (Example: Type 4 Processor) ----
TYPE4_SOCKET_DESIG   equ 0x04    ; 1 Byte: String index for Socket Designation
TYPE4_PROC_TYPE      equ 0x05    ; 1 Byte: Processor Type (Central, Boot, etc.)
TYPE4_PROC_FAMILY    equ 0x06    ; 1 Byte: Processor Family identification
TYPE4_PROC_ID        equ 0x08    ; 8 Bytes: Raw Processor ID (Features, Stepping Flags)
TYPE4_MAX_SPEED      equ 0x14    ; 2 Bytes: Maximum speed supported by the hardware (MHz)
TYPE4_CORE_COUNT     equ 0x23    ; 1 Byte: Core count available in the silicon
TYPE4_CORE_ENABLED   equ 0x24    ; 1 Byte: Cores enabled and executing instructions

; --- UNFORMATTED STRING AREA TERMINATOR --------------------------------------
; Each structure ends with a string area. Strings are null-terminated (0x00).
; The entire structure is strictly terminated by a double null byte (0x0000).
SMBIOS_STRUCT_TERM   equ 0x0000  ; End of structure marker block (Double null delimiter)



; --- CRITICAL HARDWARE STRUCTURE TYPES (The vectors rootkits try to poison) ---
SMBIOS_TYPE_BIOS     equ 0       ; Type 0: BIOS Information Block
SMBIOS_TYPE_SYSTEM   equ 1       ; Type 1: System Information Block (UUID, Model)

; ==============================================================================
;  SYSTEM MANAGEMENT BIOS (DETAILED STRUCT FIELD OFFSETS)
; ==============================================================================

; --- TYPE 0: BIOS INFORMATION STRUCTURE OFFSETS ------------------------------
T0_VENDOR_STR_IDX    equ 0x04    ; 1 Byte: String index for BIOS Vendor name
T0_BIOS_VER_STR_IDX  equ 0x05    ; 1 Byte: String index for BIOS Version string
T0_START_ADDR_SEG    equ 0x06    ; 2 Bytes: Segment address of BIOS Start (Legacy 16-bit)
T0_RELEASE_DATE_IDX  equ 0x08    ; 1 Byte: String index for BIOS Release Date
T0_ROM_SIZE          equ 0x09    ; 1 Byte: Size of the physical ROM chip layout
T0_CHARACTERISTICS   equ 0x0A    ; 8 Bytes: Supported hardware functions (PCI, ACPI, Boot)
T0_CHARACTER_EXT1    equ 0x12    ; 1 Byte: BIOS Characteristics Extension Byte 1 (R/W)
T0_CHARACTER_EXT2    equ 0x13    ; 1 Byte: BIOS Characteristics Extension Byte 2
T0_SYSTEM_MAJOR_VER  equ 0x14    ; 1 Byte: System/Embedded Controller Major Release Version
T0_SYSTEM_MINOR_VER  equ 0x15    ; 1 Byte: System/Embedded Controller Minor Release Version

; --- TYPE 1: SYSTEM INFORMATION STRUCTURE OFFSETS ----------------------------
T1_MANUFACTURER_IDX  equ 0x04    ; 1 Byte: String index for System Manufacturer name
T1_PRODUCT_NAME_IDX  equ 0x05    ; 1 Byte: String index for Product Name string
T1_VERSION_STR_IDX   equ 0x06    ; 1 Byte: String index for System Version
T1_SERIAL_NUM_IDX    equ 0x07    ; 1 Byte: String index for Serial Number string
T1_UUID_MATRIX       equ 0x08    ; 16 Bytes: Universal Unique Identifier (Hardware Fingerprint)
T1_WAKEUP_TYPE       equ 0x18    ; 1 Byte: Identifies the physical wake-up event vector
T1_SKU_NUMBER_IDX    equ 0x19    ; 1 Byte: String index for System SKU Number
T1_FAMILY_STR_IDX    equ 0x1A    ; 1 Byte: String index for System Family name

; ==============================================================================
;  SYSTEM MANAGEMENT BIOS (MOTHERBOARD & CHASSIS STRUCTURE OFFSETS)
; ==============================================================================

; --- CRITICAL HARDWARE STRUCTURE TYPES (The vectors rootkits try to poison) ---
SMBIOS_TYPE_BASEBRD  equ 2       ; Type 2: Baseboard / Motherboard Information Block
SMBIOS_TYPE_CHASSIS  equ 3       ; Type 3: System Enclosure / Chassis Matrix

; --- TYPE 2: BASEBOARD/MOTHERBOARD STRUCTURE OFFSETS ------------------------
T2_MANUFACTURER_IDX  equ 0x04    ; 1 Byte: String index for Board Manufacturer name
T2_PRODUCT_STR_IDX   equ 0x05    ; 1 Byte: String index for Board Product/Model Name
T2_VERSION_STR_IDX   equ 0x06    ; 1 Byte: String index for Board Version
T2_SERIAL_NUM_IDX    equ 0x07    ; 1 Byte: String index for Board Serial Number string
T2_ASSET_TAG_IDX     equ 0x08    ; 1 Byte: String index for Board Asset Tag identification
T2_FEATURE_FLAGS     equ 0x09    ; 1 Byte: Features (Bit 0=Hosting board, Bit 1=Replaceable)
T2_CHASSIS_HANDLE    equ 0x0A    ; 2 Bytes: Unique handle pointing to the Type 3 Structure
T2_BOARD_TYPE        equ 0x0C    ; 1 Byte: Type of board (e.g., 0x0A = Server Blade / Industrial)

; --- TYPE 3: SYSTEM ENCLOSURE/CHASSIS STRUCTURE OFFSETS ----------------------
T3_MANUFACTURER_IDX  equ 0x04    ; 1 Byte: String index for Chassis Manufacturer
T3_CHASSIS_TYPE      equ 0x05    ; 1 Byte: Type of enclosure (e.g., 0x11=Main Server Chassis)
T3_VERSION_STR_IDX   equ 0x06    ; 1 Byte: String index for Chassis Version string
T3_SERIAL_NUM_IDX    equ 0x07    ; 1 Byte: String index for Chassis Serial Number
T3_ASSET_TAG_IDX     equ 0x08    ; 1 Byte: String index for Chassis Asset Tag
T3_BOOTUP_STATE      equ 0x09    ; 1 Byte: State of enclosure when booted (Safe, Warning, Critical)
T3_POWER_SUPPLY_ST   equ 0x0A    ; 1 Byte: State of physical power supply matrix on boot
T3_THERMAL_STATE     equ 0x0B    ; 1 Byte: Thermal state of the chassis enclosure hardware
T3_SECURITY_STATUS   equ 0x0C    ; 1 Byte: Hardware Security Status (e.g., Intrusions detection)


; ==============================================================================
;  SYSTEM MANAGEMENT BIOS (PROCESSOR EXTENSIONS & MEMORY CONTROLLER OFFSETS)
; ==============================================================================

; --- CRITICAL HARDWARE STRUCTURE TYPES (The vectors rootkits try to poison) ---
SMBIOS_TYPE_PROC     equ 4       ; Type 4: Processor Information Block (Core Matrix)
SMBIOS_TYPE_MEMCTRL  equ 5       ; Type 5: Memory Controller Information Block (ECC Core)

; --- TYPE 4: PROCESSOR INFORMATION EXTENDED OFFSETS --------------------------
T4_SOCKET_DESIG_IDX  equ 0x04    ; 1 Byte: String index for Socket designation
T4_PROCESSOR_TYPE    equ 0x05    ; 1 Byte: Processor Type (Central, Secondary)
T4_PROC_FAMILY       equ 0x06    ; 1 Byte: Microarchitecture Processor Family
T4_MANUFACTURER_IDX  equ 0x07    ; 1 Byte: String index for Processor Manufacturer
T4_PROCESSOR_ID      equ 0x08    ; 8 Bytes: Silicon Feature Flags and Stepping (CPUID Matrix)
T4_VOLTAGE_CONTROL   equ 0x10    ; 1 Byte: Core voltage physical indicators
T4_EXTERNAL_CLOCK    equ 0x11    ; 2 Bytes: External Clock speed (MHz)
T4_MAX_SPEED         equ 0x13    ; 2 Bytes: Maximum frequency supported by silicon
T4_CURRENT_SPEED     equ 0x15    ; 2 Bytes: Current executing frequency (MHz)
T4_STATUS_FLAGS      equ 0x17    ; 1 Byte: Indicates if the CPU is populated and active
T4_PROC_UPGRADE      equ 0x18    ; 1 Byte: Specifies the physical socket upgrade architecture
T4_L1_CACHE_HANDLE   equ 0x1A    ; 2 Bytes: Unique handle pointing to L1 Cache structure
T4_L2_CACHE_HANDLE   equ 0x1C    ; 2 Bytes: Unique handle pointing to L2 Cache structure
T4_L3_CACHE_HANDLE   equ 0x1E    ; 2 Bytes: Unique handle pointing to L3 Cache structure
T4_CORE_COUNT        equ 0x23    ; 1 Byte: Physical core count in the silicon package
T4_CORE_ENABLED      equ 0x24    ; 1 Byte: Total active cores executing instructions
T4_THREAD_COUNT      equ 0x25    ; 1 Byte: Hardware thread count (Hyper-Threading vector)
T4_PROC_CHARACTER    equ 0x26    ; 2 Bytes: Processor Characteristics (64-bit support, NX flag)

; --- TYPE 5: MEMORY CONTROLLER INFORMATION OFFSETS ---------------------------
T5_ERR_DETECT_METHOD equ 0x04    ; 1 Byte: Error detecting method (None, Parity, ECC Matrix)
T5_ERR_CORRECT_CAP   equ 0x05    ; 1 Byte: Error correcting capability flags
T5_SUPPORT_INTERLV   equ 0x06    ; 1 Byte: Supported memory interleave configuration
T5_CURRENT_INTERLV   equ 0x07    ; 1 Byte: Currently active memory interleave mode
T5_MAX_MEM_SIZE      equ 0x08    ; 1 Byte: Maximum memory module size supported (Power of 2)
T5_SUPPORT_SPEEDS    equ 0x09    ; 2 Bytes: Supported memory speeds/voltages
T5_MEM_MODULE_HANDLES equ 0x0B   ; Variable: Array of handles for associated memory modules

; ==============================================================================
;  SYSTEM MANAGEMENT BIOS (MEMORY MODULES & PROCESSOR CACHE OFFSETS)
; ==============================================================================

; --- CRITICAL HARDWARE STRUCTURE TYPES (The vectors rootkits try to poison) ---
SMBIOS_TYPE_MEMMOD   equ 6       ; Type 6: Memory Module Information Block
SMBIOS_TYPE_CACHE    equ 7       ; Type 7: Processor Cache Information Block

; --- TYPE 6: MEMORY MODULE INFORMATION OFFSETS -------------------------------
T6_SOCKET_DESIGN     equ 0x04    ; 1 Byte: String index for physical socket designation
T6_BANK_CONNECTIONS  equ 0x05    ; 1 Byte: Identifies row and bank interconnects
T6_CURRENT_SPEED     equ 0x06    ; 1 Byte: Speed of the module in nanoseconds
T6_CURRENT_MEM_TYPE  equ 0x07    ; 2 Bytes: Module configuration flags (VRAM, SDRAM, etc.)
T6_INSTALLED_SIZE    equ 0x09    ; 1 Byte: Size of installed module (Power of 2, bit 7=Enabled)
T6_ENABLED_SIZE      equ 0x0A    ; 1 Byte: Size of enabled memory active in the socket
T6_ERROR_STATUS      equ 0x0B    ; 1 Byte: Status bits tracking memory errors (Bad bits layout)

; --- TYPE 7: PROCESSOR CACHE INFORMATION OFFSETS -----------------------------
T7_SOCKET_DESIGN     equ 0x04    ; 1 Byte: String index for cache socket designation
T7_CACHE_CONFIG      equ 0x05    ; 2 Bytes: Cache Configuration (Level, Operational Mode, Enabled bit)
T7_MAX_CACHE_SIZE    equ 0x07    ; 2 Bytes: Maximum cache size supported (1KB or 64KB granularity)
T7_INSTALLED_SIZE    equ 0x09    ; 2 Bytes: Installed cache size currently active in hardware
T7_SUPPORTED_SRAM    equ 0x0B    ; 2 Bytes: Supported SRAM types (Synchronous, Burst, Pipeline)
T7_CURRENT_SRAM      equ 0x0D    ; 2 Bytes: Active SRAM type operating in the silicon
T7_CACHE_SPEED       equ 0x0F    ; 1 Byte: Speed of the cache module in nanoseconds
T7_ERR_CORRECT_TYPE  equ 0x10    ; 1 Byte: Error correction mechanism (None, Parity, Multi-bit ECC)
T7_SYSTEM_CACHE_TYPE equ 0x11    ; 1 Byte: Logical system cache type (Instruction, Data, Unified)
T7_ASSOCIATIVITY     equ 0x12    ; 1 Byte: Cache associativity map (Direct Mapped, 2-way, 4-way, etc.)

; ==============================================================================
;  SYSTEM MANAGEMENT BIOS (PORT CONNECTORS & PCI EXPANSION SLOTS OFFSETS)
; ==============================================================================

; --- CRITICAL HARDWARE STRUCTURE TYPES (The vectors rootkits try to poison) ---
SMBIOS_TYPE_PORTCONN equ 8       ; Type 8: Port Connector Information Block
SMBIOS_TYPE_SYSSLOTS equ 9       ; Type 9: System Slots / PCI Express Information Block

; --- TYPE 8: PORT CONNECTOR INFORMATION OFFSETS ------------------------------
T8_INT_DESIGNATOR    equ 0x04    ; 1 Byte: String index for internal reference designator
T8_INT_CONN_TYPE     equ 0x05    ; 1 Byte: Internal connector physical type (e.g., SATA, IDE)
T8_EXT_DESIGNATOR    equ 0x06    ; 1 Byte: String index for external reference designator
T8_EXT_CONN_TYPE     equ 0x07    ; 1 Byte: External connector physical type (e.g., USB, Serial)
T8_PORT_TYPE         equ 0x08    ; 1 Byte: Logical port type (e.g., Network, Serial, Mouse)

; --- TYPE 9: SYSTEM SLOTS / PCI EXPRESS OFFSETS ------------------------------
T9_SLOT_DESIGNATOR   equ 0x04    ; 1 Byte: String index for physical slot designation
T9_SLOT_TYPE         equ 0x05    ; 1 Byte: Slot type (e.g., 0xA5 = PCI Express x16, 0xA6 = PCIe x8)
T9_SLOT_DATA_BUS_WID equ 0x06    ; 1 Byte: Data bus width (e.g., 1x, 4x, 8x, 16x lanes)
T9_CURRENT_USAGE     equ 0x07    ; 1 Byte: Current slot utilization state (Available, In Use)
T9_SLOT_LENGTH       equ 0x08    ; 1 Byte: Physical slot length (Short, Long)
T9_SLOT_ID           equ 0x09    ; 2 Bytes: Unique allocation slot identifier number
T9_SLOT_CHARACTER    equ 0x0B    ; 2 Bytes: Slot characteristics (Supports 3.3V, PME#, Hot-Plug)
T9_SEGMENT_GROUP_NUM equ 0x0D    ; 2 Bytes: Base PCI Segment Group Number for mapping
T9_BUS_NUM           equ 0x0F    ; 1 Byte: Exact physical PCI Bus Number associated
T9_DEV_FUNC_NUM      equ 0x10    ; 1 Byte: Packed PCI Device (Bits 7:3) and Function (Bits 2:0) Number

; ==============================================================================
; 10. SYSTEM MANAGEMENT BIOS (OEM STRINGS & BIOS LANGUAGE OFFSETS)
; ==============================================================================

; --- CRITICAL HARDWARE STRUCTURE TYPES (The vectors rootkits try to poison) ---
SMBIOS_TYPE_OEMSTR   equ 11      ; Type 11: OEM Strings Information Block
SMBIOS_TYPE_SYSCONFIG equ 12      ; Type 12: System Configuration Options Block
SMBIOS_TYPE_BIOSLANG equ 13      ; Type 13: BIOS Language Information Block

; --- TYPE 11: OEM STRINGS INFORMATION OFFSETS --------------------------------
T11_COUNT            equ 0x04    ; 1 Byte: Total number of OEM strings packed inside this structure

; --- TYPE 12: SYSTEM CONFIGURATION OPTIONS OFFSETS ---------------------------
T12_COUNT             equ 0x04    ; 1 Byte: Total number of configuration strings packed inside


; --- TYPE 13: BIOS LANGUAGE INFORMATION OFFSETS ------------------------------
T13_INSTALL_LANGS    equ 0x04    ; 1 Byte: Total number of languages installed in the hardware ROM
T13_FLAGS            equ 0x05    ; 1 Byte: Language flags (Bit 0 = Current language notation format)
T13_RESERVED         equ 0x06    ; 15 Bytes: Reserved field for structural compliance alignment
T13_CURRENT_LANG_IDX equ 0x15    ; 1 Byte: String index for the currently active BIOS language selection

;now there is your signature and near then we doing Type 0, 1, 2, 3, 4, 5, 6, 7, 8 ,9 ,10, 11, 12, 13
