#ifndef EXBFMT_H
#define EXBFMT_H

typedef enum {
    EXB_PLAIN,
    EXB_ENCRYPTED,
    EXB_NONE
} EXBType;

typedef struct
{
    size_t s_index;
    char *s_name;
    size_t s_size;
    uint8_t *s_hash;
} EXBFileSectionMeta;

typedef struct
{
    int bin_class;
    char *bin_type;
    size_t bin_size;
    size_t bin_sections_size;
    int bin_section_num;
    EXBFileSectionMeta **bin_sections;
    size_t bin_shared_libs_size;
    int bin_shared_libs_num;
    char **bin_shared_libs;
    double bin_shannon_entropy;
} EXBFileData;

typedef struct
{
    EXBType exb_type;
    size_t exb_size;
    size_t exb_enc_size;
    EXBFileData *exb_data;
} EXBFileHeader;

typedef EXBFileHeader EXBFile;

EXBFile *exb_init();
void exb_deinit(EXBFile *);

EXBFileData *exb_d_init();
void exb_d_deinit(EXBFileData *);

EXBFileSectionMeta *exb_s_meta_init(int index, char *name, size_t size, uint8_t *hash);
void exb_s_meta_deinit(EXBFileSectionMeta *);

char *exb_d_tostr(EXBFileData *, size_t *);
char *exb_s_tostr(EXBFileSectionMeta *, size_t *);
char* exb_f_tostr(EXBFile*, size_t*);

int exb_save_plain(EXBFile *, char *);
int exb_save_enc(EXBFile *, char *, char*);
EXBFile* exb_load(char*);
EXBFile* exb_load_header(FILE*);
EXBFile* exb_load_data(EXBFile*, char*, char*);

char* prompt_for_key();

char *convert_ui8arrtostr(uint8_t *a, size_t);
char *exb_sectionstostr(EXBFileSectionMeta **sections, int, size_t *size);

size_t calcDecodeLength(const char* b64input);
int Base64Encode(const unsigned char* buffer, size_t length, char** b64text);
int Base64Decode(char* b64message, unsigned char** buffer, size_t* length);

void exb_print(EXBFile*);

#endif // EXBFMT_H