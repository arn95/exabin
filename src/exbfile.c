#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/blowfish.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <assert.h>
#include "exbfile.h"

EXBFile *exb_init()
{
    /*
    EXBType exb_type; -
    size_t exb_enc_size;
    size_t exb_size;
    EXBFileData* exb_data;
    */

    EXBFile *file = (EXBFile *)malloc(sizeof(EXBFile));
    if (file != NULL)
    {
        file->exb_type = EXB_NONE;
        file->exb_enc_size = 0;
        file->exb_size = 0;
        file->exb_data = NULL;
    }

    return file;
}

void exb_deinit(EXBFile *file)
{
    if (file != NULL)
    {
        exb_d_deinit(file->exb_data);
        free(file);
    }
}

EXBFileData *exb_d_init()
{
    /*
    int bin_class;
    char* bin_type;
    size_t bin_size;
    int bin_section_num;
    EXBFileSectionMeta **bin_sections;
    int bin_shared_libs_num;
    char **bin_shared_libs;
    double bin_shannon_entropy;
    */

    EXBFileData *data = (EXBFileData *)malloc(sizeof(EXBFileData));
    if (data != NULL)
    {
        data->bin_class = 0;
        data->bin_type = NULL;
        data->bin_sections_size = 0;
        data->bin_section_num = 0;
        data->bin_sections = NULL;
        data->bin_shared_libs_size = 0;
        data->bin_shared_libs_num = 0;
        data->bin_shared_libs = NULL;
        data->bin_shannon_entropy = 0;
    }

    return data;
}

void exb_d_deinit(EXBFileData *data)
{
    if (data != NULL)
    {
        if (data->bin_sections != NULL)
        {

            int i = 0;
            for (; i < data->bin_section_num; i++)
            {
                exb_s_meta_deinit(data->bin_sections[i]);
            }
            free(data->bin_sections);
        }

        if (data->bin_shared_libs != NULL)
        {
            int i = 0;
            for (; i < data->bin_shared_libs_num; i++)
            {
                free(data->bin_shared_libs[i]);
            }
            free(data->bin_shared_libs);
        }

        free(data);
    }
}

EXBFileSectionMeta *exb_s_meta_init(int index, char *name, size_t size, uint8_t *hash)
{
    /*
    int s_index;
    char *s_name;
    size_t s_size;
    uint8_t *s_hash;
    */

    EXBFileSectionMeta *section = (EXBFileSectionMeta *)malloc(sizeof(EXBFileSectionMeta));
    if (section != NULL)
    {
        section->s_index = index;
        section->s_name = strdup(name);
        section->s_size = size;
        section->s_hash = (uint8_t *)malloc(16 * sizeof(uint8_t));
        memcpy(section->s_hash, hash, 16);
    }

    return section;
}

void exb_s_meta_deinit(EXBFileSectionMeta *section)
{
    if (section != NULL)
    {
        if (section->s_name != NULL)
            free(section->s_name);
        if (section->s_hash != NULL)
            free(section->s_hash);

        free(section);
    }
}

char *exb_d_tostr(EXBFileData *data, size_t *size)
{

    /*
    int bin_class;
    char* bin_type;
    size_t bin_size;
    int bin_section_num;
    EXBFileSectionMeta **bin_sections;
    int bin_shared_libs_num;
    char **bin_shared_libs;
    double bin_shannon_entropy;
    */

    char *d_str = NULL;

    if (data != NULL)
    {

        size_t bin_sections_size;
        char *bin_sections = exb_sectionstostr(data->bin_sections, data->bin_section_num, &bin_sections_size);

        data->bin_sections_size = bin_sections_size;

        if (bin_sections == NULL)
            bin_sections = "NULL";

        int size_factor = 300;
        char *bin_shared_libs = (char *)malloc((300) * sizeof(char));
        bin_shared_libs[0] = '\0';

        int used_len = 0;

        int i;
        for (i = 0; i < data->bin_shared_libs_num; i++)
        {

            char *lib = data->bin_shared_libs[i];
            int lib_len = strlen(lib);

            if ((lib_len + strlen(bin_shared_libs)) > size_factor)
            {
                size_factor *= 2;
                bin_shared_libs = (char *)realloc(bin_shared_libs, size_factor * sizeof(char));
            }

            if (used_len != 0)
                strcat(bin_shared_libs, " ");
            strcat(bin_shared_libs, lib);
            used_len++; //for "\n";
            used_len += lib_len;
        }

        if (used_len > 0)
        {
            bin_shared_libs = (char *)realloc(bin_shared_libs, used_len + 1 * sizeof(char));
            bin_shared_libs[used_len + 1] = '\0';
            data->bin_shared_libs_size = used_len;
        }
        else
        {
            free(bin_shared_libs);
            bin_shared_libs = NULL;
            data->bin_shared_libs_size = 0;
        }

        if (bin_shared_libs == NULL)
            bin_shared_libs = "NULL";

        d_str = NULL;
        *size = asprintf(&d_str, "%d %s %zu %d\n%s\n%zu %d\n%s\n%lf\n",
                         data->bin_class,
                         data->bin_type,
                         data->bin_sections_size,
                         data->bin_section_num,
                         bin_sections,
                         data->bin_shared_libs_size,
                         data->bin_shared_libs_num,
                         bin_shared_libs,
                         data->bin_shannon_entropy);

        //clean

        if (bin_sections != NULL && strcmp(bin_sections, "NULL") != 0)
        {
            free(bin_sections);
        }

        if (bin_shared_libs != NULL && strcmp(bin_shared_libs, "NULL") != 0)
        {
            free(bin_shared_libs);
        }
    }
    else
    {
        *size = asprintf(&d_str, "%s", "NULL");
    }

    return d_str;
}

char *exb_s_tostr(EXBFileSectionMeta *section, size_t *size)
{
    char *s_str = NULL;

    if (section != NULL)
    {

        /*
            size_t s_index;
    char *s_name;
    size_t s_size;
    uint8_t* s_hash;
    */
        char *s_hash_str = convert_ui8arrtostr(section->s_hash, 16);
        *size = asprintf(&s_str, "%zu %s %zu %s\n", section->s_index, section->s_name, section->s_size, s_hash_str);
        if (s_hash_str != NULL)
            free(s_hash_str);
    }
    else
    {
        *size = asprintf(&s_str, "%s", "NULL");
    }

    return s_str;
}

int exb_d_save(EXBFileData *data, FILE *file)
{
    int err = 0;

    if (data != NULL && file != NULL)
    {
        size_t size;
        char *d_struct = exb_d_tostr(data, &size);
        int written = fwrite(d_struct, size, 1, file);
        if (written == 1)
        {
            fprintf(stdout, "Wrote EXB Data.");
        }
        else
        {
            fprintf(stderr, "Failed to write EXB Data.\n");
            err = 1;
        }
    }
    else
    {
        err = 1;
    }

    return err;
}

char *exb_f_tostr(EXBFile *exb, size_t *size)
{
    char *f_str = NULL;

    if (exb != NULL)
    {
        size_t data_size;
        char *exb_data = exb_d_tostr(exb->exb_data, &data_size);
        exb->exb_size = (sizeof(exb->exb_type) + data_size + sizeof(exb->exb_size) + sizeof(exb->exb_enc_size));
        *size = asprintf(&f_str, "EXB %d %zu %zu\n%s", exb->exb_type, exb->exb_size, exb->exb_enc_size, exb_data);
        free(exb_data);
    }
    else
    {
        *size = asprintf(&f_str, "%s", "NULL");
    }

    return f_str;
}

char *exb_sectionstostr(EXBFileSectionMeta **sections, int section_num, size_t *size)
{
    if (sections != NULL)
    {

        int size_factor = 300;
        int used_len = 0;

        char *sections_str = (char *)malloc(size_factor * sizeof(char));
        sections_str[0] = '\0';

        int i;
        for (i = 0; i < section_num; i++)
        {
            // EXBFileSectionMeta *section = sections[i];
            // size_t size;
            // char *s_str = exb_s_tostr(section, &size);
            // int bytes = fwrite(s_str, size, 1, file);
            // if (bytes != 1)
            // {
            //     err = 1;
            // }
            EXBFileSectionMeta *section = sections[i];

            size_t size;
            char *section_str = exb_s_tostr(section, &size);

            if ((size + used_len) > size_factor)
            { //need realloc
                size_factor *= 2;
                sections_str = (char *)realloc(sections_str, size_factor * sizeof(char));
            }
            strcat(sections_str, section_str);
            used_len += strlen(section_str);
        }

        if (used_len > 0)
        {
            sections_str = (char *)realloc(sections_str, used_len + 1 * sizeof(char)); //+1 for '\0'
            sections_str[used_len + 1] = '\0';
            *size = used_len;
        }
        else
        {
            free(sections_str);
            sections_str = NULL;
            *size = 0;
        }

        return sections_str;
    }

    *size = 0;
    return NULL;
}

int exb_save_plain(EXBFile *exb, char *path)
{

    char *filepath;
    asprintf(&filepath, "%s.exb", path);
    FILE *file = fopen(filepath, "w");
    int err = 0;

    if (file == NULL)
    {
        fprintf(stderr, "Failed to open: %s\n", filepath);
        err = 1;
    }

    exb->exb_type = EXB_PLAIN;

    size_t file_size;
    char *file_str = exb_f_tostr(exb, &file_size);

    int written = fwrite(file_str, file_size, 1, file);

    if (written != 0)
    {
        fprintf(stdout, "Wrote %zu bytes.\n", file_size);
        err = 0;
    }
    else
    {
        fprintf(stderr, "Failed to write file contents.\n");
        err = 1;
    }

    fclose(file);
    free(file_str);
    free(filepath);

    return err;
}

int exb_save_enc(EXBFile *exb, char *path, char *passphrase)
{

    char *key = strdup(passphrase);

    char *filepath;
    asprintf(&filepath, "%s.exb", path);
    FILE *file = fopen(filepath, "w");
    int err = 0;

    if (file == NULL)
    {
        fprintf(stderr, "Failed to open: %s\n", filepath);
        err = 1;
    }

    exb->exb_type = EXB_ENCRYPTED;

    size_t data_size;
    char *exb_data_str = exb_d_tostr(exb->exb_data, &data_size);

    //encode data section

    char *appendix = (char *)malloc(2 * sizeof(char));
    appendix[0] = ':';
    appendix[1] = '\0';

    appendix = strcat(appendix, key);
    exb_data_str = strcat(exb_data_str, appendix);

    data_size += strlen(appendix);

    char *b64_out;
    Base64Encode((const unsigned char *)exb_data_str, data_size, &b64_out);

    exb->exb_size = (sizeof(exb->exb_type) + data_size + sizeof(exb->exb_size) + sizeof(exb->exb_enc_size));

    free((void *)exb_data_str);

    exb->exb_enc_size = strlen(b64_out);

    char *file_str;
    size_t file_size = asprintf(&file_str, "EXB %d %zu %zu\n%s", exb->exb_type, exb->exb_size, exb->exb_enc_size, b64_out);

    int written = fwrite(file_str, file_size, 1, file);

    if (written != 0)
    {
        fprintf(stdout, "Wrote %zu bytes.\n", file_size);
        err = 0;
    }
    else
    {
        fprintf(stderr, "Failed to write file contents.\n");
        err = 1;
    }

    fclose(file);

    free(filepath);
    free(key);

    return err;
}

EXBFile *exb_load(char *path)
{

    FILE *file = fopen(path, "r");

    if (file == NULL)
    {
        fprintf(stderr, "Failed to open: %s\n", path);
        return NULL;
    }

    return exb_load_header(file);
}

EXBFile *exb_load_enc(FILE *file)
{
    return NULL;
}

char *convert_ui8arrtostr(uint8_t *a, size_t count)
{
    if (count < 1)
    {
        return NULL;
    }

    const char *table[] = {
        "0000", "0001", "0010", "0011",
        "0100", "0101", "0110", "0111",
        "1000", "1001", "1010", "1011",
        "1100", "1101", "1110", "1111"};

    size_t buffer_size = 8 * count + 1;
    char *buffer = malloc(buffer_size);
    if (buffer == NULL)
    {
        return NULL;
    }

    char *output = buffer;
    for (int i = 0; i < count; i++)
    {
        memcpy(output, table[a[i] >> 4], 4);
        output += 4;
        memcpy(output, table[a[i] & 0x0F], 4);
        output += 4;
    }

    *output = 0;

    return buffer;
}

EXBFile *exb_load_header(FILE *file)
{

    if (file == NULL)
    {
        fprintf(stderr, "File pointer null.\n");
        return NULL;
    }

    EXBFile *exb = exb_init();

    int h_items = 0;

    int offset = 0;

    if (!feof(file))
    {
        h_items = fscanf(file, "EXB %d %zu %zu\n", &exb->exb_type, &exb->exb_size, &exb->exb_enc_size);
    }

    if (h_items == 3)
    {

        if (exb->exb_type == EXB_ENCRYPTED)
        {
            size_t data_size = exb->exb_size - sizeof(exb->exb_type) - sizeof(exb->exb_size) - sizeof(exb->exb_enc_size);

            char *key = prompt_for_key();
            
            if (key == NULL)
            {
                fprintf(stderr, "Invalid key\n");
                return NULL;
            }

            char *encoded_data = (char *)malloc(exb->exb_enc_size * sizeof(char));
            int items = 0;
            items = fread(encoded_data, exb->exb_enc_size, 1, file);

            if (items == 1)
            {

                //Decode from b64

                fclose(file);

                unsigned char *decoded_data;
                size_t decoded_data_size;
                Base64Decode(encoded_data, &decoded_data, &decoded_data_size);
                return exb_load_data(exb, (char *)decoded_data, key);
            }
            else
            {
                fclose(file);
                fprintf(stderr, "Could not read encrypted data.\n");
                return NULL;
            }
        }
        else
        {
            size_t data_size = exb->exb_size - sizeof(exb->exb_type) - sizeof(exb->exb_size) - sizeof(exb->exb_enc_size);
            char *exb_data = (char *)malloc(data_size * sizeof(char));
            int d_items = fread(exb_data, data_size, 1, file);
            if (d_items == 1)
            {
                fclose(file);
                return exb_load_data(exb, exb_data, NULL);
            }
            else
            {
                fprintf(stderr, "Malformed EXB data.\n");
                return NULL;
            }
        }
    }
    else
    {
        fclose(file);
        fprintf(stderr, "Malformed EXB header.\n");
        return NULL;
    }
}

EXBFile *exb_load_data(EXBFile *exb, char *exb_data, char *key)
{

    EXBFileData *data = exb_d_init();
    char *bin_type = (char *)malloc(30 * sizeof(char));
    int offset = 0;
    int d_items = sscanf(exb_data, "%d %s %zu %d\n%n", //
                         &data->bin_class,
                         bin_type,
                         &data->bin_sections_size,
                         &data->bin_section_num,
                         &offset);

    if (d_items == 4)
    {

        exb_data = exb_data + offset;

        data->bin_type = bin_type;

        EXBFileSectionMeta **sections = (EXBFileSectionMeta **)malloc(data->bin_section_num * sizeof(EXBFileSectionMeta *));

        size_t s_index = 0;
        char s_name[30];
        size_t s_size = 0;
        char s_hash_str[128];

        int count = 0;
        int s_items = 0;
        while ((s_items = sscanf(exb_data, "%zu %s %zu %s\n%n", &s_index, s_name, &s_size, s_hash_str, &offset)) == 4 && count < data->bin_section_num)
        {
            EXBFileSectionMeta *section = exb_s_meta_init(s_index, s_name, s_size, (uint8_t *)s_hash_str);
            sections[count++] = section;
            exb_data = exb_data + offset;
        }

        if (s_items != 2)
        {
            fprintf(stderr, "Malformed sections.\n");
            exb_d_deinit(data);
            return NULL;
        }

        data->bin_sections = sections;

        int sl_meta_items = sscanf(exb_data, "%zu %d\n%n", &data->bin_shared_libs_size, &data->bin_shared_libs_num, &offset);

        if (sl_meta_items == 2)
        {

            exb_data = exb_data + offset;

            char **libs = (char **)malloc(data->bin_shared_libs_num * sizeof(char *));

            int sl_items = 0;
            char lib[30];
            int count = 0;
            while ((sl_items = sscanf(exb_data, "%s %n", lib, &offset)) == 1 && (count < data->bin_shared_libs_num))
            {
                libs[count++] = strdup(lib);
                exb_data = exb_data + offset;
            }

            data->bin_shared_libs = libs;

            int ent_items = 0;
            if ((ent_items = sscanf(exb_data, "%lf\n%n", &data->bin_shannon_entropy, &offset)) == 1)
            {

                exb_data = exb_data + offset;

                if (exb->exb_type == EXB_ENCRYPTED)
                {
                    int user_items = 0;
                    char passphrase[50];
                    if ((user_items = sscanf(exb_data, ":%s", passphrase)) == 1)
                    {
                        if (strcmp(passphrase, key) == 0)
                        {
                            fprintf(stderr, "EXB file loaded.\n");
                            exb->exb_data = data;
                            return exb;
                        }
                        else
                        {
                            fprintf(stderr, "Wrong passphrase.\n");
                            exb_d_deinit(data);
                            return NULL;
                        }
                    }
                    else
                    {
                        fprintf(stderr, "Malformed passphrase.\n");
                        exb_d_deinit(data);
                        return NULL;
                    }
                }
                else
                {
                    exb->exb_data = data;
                    return exb;
                }
            }
            else
            {
                fprintf(stderr, "Malformed shannon entropy.\n");
                exb_d_deinit(data);
                return NULL;
            }
        }
        else
        {
            fprintf(stderr, "Malformed shared libs.\n");
            exb_d_deinit(data);
            return NULL;
        }
    }
    else
    {
        fprintf(stderr, "Malformed EXB data or encrypted.\n");
        exb_d_deinit(data);
        return NULL;
    }
}

char *prompt_for_key()
{

    fprintf(stdout, "Enter key to unlock EXB: ");
    char line[50];
    if (fgets(line, sizeof(line), stdin))
    {
        char key[50];
        if (1 == sscanf(line, "%s", key))
        {
            return strdup(key);
        }
    }

    return NULL;
}

size_t calcDecodeLength(const char *b64input)
{ //Calculates the length of a decoded string
    size_t len = strlen(b64input),
           padding = 0;

    if (b64input[len - 1] == '=' && b64input[len - 2] == '=') //last two chars are =
        padding = 2;
    else if (b64input[len - 1] == '=') //last char is =
        padding = 1;

    return (len * 3) / 4 - padding;
}

int Base64Encode(const unsigned char *buffer, size_t length, char **b64text)
{ //Encodes a binary safe base 64 string
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Ignore newlines - write everything in one line
    BIO_write(bio, buffer, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free_all(bio);

    *b64text = (*bufferPtr).data;

    return (0); //success
}

int Base64Decode(char *b64message, unsigned char **buffer, size_t *length)
{ //Decodes a base64 encoded string
    BIO *bio, *b64;

    int decodeLen = calcDecodeLength(b64message);
    *buffer = (unsigned char *)malloc(decodeLen + 1);
    (*buffer)[decodeLen] = '\0';

    bio = BIO_new_mem_buf(b64message, -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Do not use newlines to flush buffer
    *length = BIO_read(bio, *buffer, strlen(b64message));
    assert(*length == decodeLen); //length should equal decodeLen, else something went horribly wrong
    BIO_free_all(bio);

    return (0); //success
}