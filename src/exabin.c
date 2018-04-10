#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <libelf.h>
#include <gelf.h>
#include <ctype.h>
#include <dlfcn.h>
#include <openssl/md5.h>
#include <math.h>

#include "exbfile.h"
#include "map.h"
#include "exabin.h"

extern int bitcount(char onebyte);

EXBFile *exb;

int main(int argc, char *argv[])
{

    if (check_deps() == EXIT_FAILURE)
    {
        return EXIT_FAILURE;
    }

    parse_args(argc, argv);

    // if (argc > 1)
    // { // it already includes exabin so 1

    //     char *bin_path = argv[1];

    // }
    // else
    // {
    //     printusage(argv[0], "Path to ELF binary not specified.");
    // }
}

int parse_args(int argc, char *argv[])
{

    int s_flag = 0;
    int e_flag = 0;
    int b_flag = 0;
    int l_flag = 0;
    int c;
    int index;
    char *passphrase, *bin_path, *load_path;

    opterr = 0;

    while ((c = getopt(argc, argv, "e:l:b:s")) != -1)
        switch (c)
        {
        case 's':
            s_flag = 1;
            break;
        case 'e':
            e_flag = 1;
            passphrase = optarg;
            break;
        case 'b':
            b_flag = 1;
            bin_path = optarg;
            break;
        case 'l':
            l_flag = 1;
            load_path = optarg;
        case '?':
            if (optopt == 'e')
                fprintf(stderr, "Option -%c requires an argument.\n", optopt);
            else if (isprint(optopt))
                fprintf(stderr, "Unknown option `-%c'.\n", optopt);
            else
                fprintf(stderr,
                        "Unknown option character `\\x%x'.\n",
                        optopt);
            return 1;
        default:
            abort();
        }

    if (b_flag == 1)
    {

        int open_fd;
        Elf *e = open_elf_file(bin_path, &open_fd);
        if (e != NULL)
        {
            exb = exb_init();

            EXBFileData *exb_data = print_elf_info(e);
            exb->exb_data = exb_data;

            close_elf_file(open_fd, e);

            double ent = calc_entropy(bin_path);
            exb->exb_data->bin_shannon_entropy = ent;

            fprintf(stdout, "\nShannon Entropy: %lf\n", ent);

            // int encrypt;
            // char *passphrase;
            // if (prompt_to_save(&encrypt, &passphrase) != 1)
            // {
            //     if (encrypt == 0)
            //     {
            //         exb_save_enc(exb, bin_path, passphrase);
            //     }
            //     else
            //     {
            //         exb_save_plain(exb, bin_path);
            //     }
            // }

            //exb_load("bin/access.dms.exb");

            exb_deinit(exb);
        }
    }
    else if (l_flag == 1)
    {
        exb = exb_load(load_path);

    }

    for (index = optind; index < argc; index++)
        printf("Non-option argument %s\n", argv[index]);
    return 0;
}

void printusage(char *name, char *message)
{
    fprintf(stdout, "usage: %s /path/to/binary\n%s\n", name, message);
}

int check_deps()
{
    if (elf_version(EV_CURRENT) == EV_NONE)
    {
        perror("libelf not found.\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

Elf *open_elf_file(char *path, int *fde)
{

    int fd = open(path, O_RDONLY); //open file

    if (!fd)
    {
        fprintf(stderr, "%s cannot be opened.\n", path);
        return NULL;
    }

    Elf *elf_file = elf_begin(fd, ELF_C_READ, NULL);

    if (!elf_file)
    {
        perror("ELF file could not be opened.\n");
        close(fd);
        return NULL;
    }

    if (elf_kind(elf_file) != ELF_K_ELF)
    {
        fprintf(stderr, "%s is not an ELF file.\n", path);
        close(fd);
        return NULL;
    }

    *fde = fd;

    return elf_file;
}

void close_elf_file(int fd, Elf *e)
{
    elf_end(e);
    close(fd);
}

EXBFileData *print_elf_info(Elf *elf_file)
{

    EXBFileData *exb_data = NULL;

    fprintf(stdout, "\n%s\n", "---- ELF Info ----");

    GElf_Ehdr ehdr;

    if (gelf_getehdr(elf_file, &ehdr) == NULL)
    {
        perror("Cannot read ELF header.");
        return exb_data;
    }

    exb_data = exb_d_init();

    int class = gelf_getclass(elf_file);
    int classprint = 0;
    switch (class)
    {
    case ELFCLASS32:
        classprint = 32;
        break;
    case ELFCLASS64:
        classprint = 64;
        break;
    }
    fprintf(stdout, "Class: %d\n", classprint);

    exb_data->bin_class = classprint;

    char *type = NULL;
    switch (ehdr.e_type)
    {
    case ET_NONE:
        type = "None";
        break;
    case ET_REL:
        type = "Relocatable";
        break;
    case ET_EXEC:
        type = "Executable";
        break;
    case ET_DYN:
        type = "Shared Object";
        break;
    case ET_CORE:
        type = "Core";
        break;
    default:
        type = "None";
    }
    fprintf(stdout, "Type: %s\n", type);

    exb_data->bin_type = type;

    size_t file_size = ehdr.e_shoff + (ehdr.e_shentsize * ehdr.e_shnum);

    fprintf(stdout, "Size: %zu bytes\n", file_size);

    // print meta for each section

    size_t sh_str_i = 0;
    Elf_Scn *section = NULL;
    if (elf_getshdrstrndx(elf_file, &sh_str_i) != 0)
    {
        perror("Cannot read section header string index.\n");
        return exb_data;
    }

    fprintf(stdout, "Sections: \n");

    int max_section_size = 30;
    exb_data->bin_sections = (EXBFileSectionMeta **)malloc(max_section_size * sizeof(EXBFileSectionMeta *));

    //iterate over every section
    while ((section = elf_nextscn(elf_file, section)) != NULL)
    {
        GElf_Shdr section_hdr;
        if (gelf_getshdr(section, &section_hdr) != NULL)
        {
            EXBFileSectionMeta *section_meta = print_section_meta(elf_file, section, &section_hdr, sh_str_i);

            if (section_meta != NULL)
            {
                if (strcmp(section_meta->s_name, ".dynamic") == 0)
                {
                    size_t shared_libs_num;
                    char **shared_libs = print_dynamic_section_contents(elf_file, section, &section_hdr, &shared_libs_num);
                    exb_data->bin_shared_libs = shared_libs;
                    exb_data->bin_shared_libs_num = shared_libs_num;
                }

                //too many sections. need realloc
                if (exb_data->bin_section_num > max_section_size)
                {
                    // increase size of array by a factor of 2
                    exb_data->bin_sections = (EXBFileSectionMeta **)realloc(exb_data->bin_sections, (max_section_size * 2) * sizeof(EXBFileSectionMeta *));
                    max_section_size *= 2;
                }

                exb_data->bin_sections[exb_data->bin_section_num++] = section_meta;
            }
        }
        else
        {
            perror("gelf_getshdr failed.\n");
        }
    }

    if (exb_data->bin_section_num > 0)
    {
        //adjust size based on total sections
        exb_data->bin_sections = (EXBFileSectionMeta **)realloc(exb_data->bin_sections, exb_data->bin_section_num * sizeof(EXBFileSectionMeta *));
    }
    else
    {
        free(exb_data->bin_sections);
        exb_data->bin_sections = NULL;
    }

    fprintf(stdout, "%s\n", "--------------");

    return exb_data;
}

double my_log2(double n)
{
    // log(n)/log(2) is log2.
    return log(n) / log(2);
}

double calc_entropy(char *path)
{

    FILE *file = fopen(path, "rb");
    int len = 0;
    int onesCount = 0;
    int zerosCount = 0;
    double result = 0.0;

    if (file != NULL)
    {
        char character = '\0';
        while (1)
        {
            char read_size = fread(&character, sizeof(char), sizeof(char), file);
            if (read_size > 0)
            {
                int ones = bitcount(character);
                int zeros = (8 - ones);
                onesCount += ones;
                zerosCount += zeros;
                len += 8;
            }
            else
            {
                break;
            }
        }
    }
    else
    {
        fprintf(stderr, "Failed to open: %s", path);
        return -1;
    }

    double freq1 = (double)onesCount / len;
    double freq0 = (double)zerosCount / len;

    result -= freq1 * my_log2(freq1);
    result -= freq0 * my_log2(freq0);

    fclose(file);

    return result;
}

char **print_dynamic_section_contents(Elf *elf, Elf_Scn *scn, GElf_Shdr *shdr, size_t *sym_num)
{
    Elf_Data *data;
    size_t cnt;

    /* Get the data of the section.  */
    data = elf_getdata(scn, NULL);
    if (data == NULL)
        return NULL;

    int max_shared_libs = 10;
    char **shared_libs = (char **)malloc(max_shared_libs * sizeof(char *));
    int shared_libs_num = 0;

    fprintf(stdout, "\n%6s %s\n", " ", "Shared Libs:");

    for (cnt = 0; cnt < shdr->sh_size / shdr->sh_entsize; ++cnt)
    {
        GElf_Dyn dynmem;
        GElf_Dyn *dyn = gelf_getdyn(data, cnt, &dynmem);
        if (dyn == NULL)
            break;

        if (dyn->d_tag == DT_NEEDED)
        {
            char *libname = elf_strptr(elf, shdr->sh_link, dyn->d_un.d_val);
            fprintf(stdout, "%10s %s\n", " ", libname);
            if (shared_libs_num > max_shared_libs)
            {
                shared_libs = (char **)realloc(shared_libs, (max_shared_libs * 2) * sizeof(char *));
                max_shared_libs *= 2;
            }
            shared_libs[shared_libs_num++] = strdup(libname);
        }
    }

    if (shared_libs_num > 0)
    {
        *sym_num = shared_libs_num;
        shared_libs = (char **)realloc(shared_libs, (shared_libs_num) * sizeof(char *));
    }
    else
    {
        *sym_num = 0;
        free(shared_libs);
        shared_libs = NULL;
    }

    fprintf(stdout, "\n");

    return shared_libs;
}

EXBFileSectionMeta *print_section_meta(Elf *elf_file, Elf_Scn *section, GElf_Shdr *scn_hdr, int sh_str_i)
{
    EXBFileSectionMeta *sm = NULL;

    size_t s_index = 0;
    char *s_name = NULL;
    size_t s_size = 0;
    uint8_t *s_hash = NULL;

    s_name = elf_strptr(elf_file, sh_str_i, scn_hdr->sh_name);
    if (s_name != NULL && scn_hdr->sh_type != SHT_NOBITS && scn_hdr->sh_type != SHT_NULL)
    {
        s_index = elf_ndxscn(section);
        s_size = scn_hdr->sh_size;

        fprintf(stdout, "%3s %-4.4zu %-20.15s size: %-10zu %5s ", " ", s_index, s_name, s_size, "MD5: ");

        MD5_CTX CTX;
        int count = 0;
        Elf_Data *data = NULL;
        while ((data = elf_getdata(section, data)) != NULL)
        {
            if (count == 0)
            {
                MD5_Init(&CTX);
            }

            if (data->d_buf != 0 || data->d_size > 0)
            {
                MD5_Update(&CTX, data->d_buf, data->d_size);
                count++;
            }
        }
        if (count > 0)
        {
            uint8_t md[MD5_DIGEST_LENGTH];
            if (MD5_Final(md, &CTX) == 1)
            {
                s_hash = md;

                sm = exb_s_meta_init(s_index, strdup(s_name), s_size, s_hash);

                int i;
                for (i = 0; i < MD5_DIGEST_LENGTH; i++)
                {
                    fprintf(stdout, "%02x", md[i]);
                }
            }
        }

        fprintf(stdout, "\n");

        return sm;
    }
    else
    {
        return NULL;
    }
}

int prompt_to_save(int *encrypt, char **passphrase)
{
    char line[50];

    fprintf(stdout, "Do you wish to save? (y/n) ");

    char c;
    if (fgets(line, sizeof(line), stdin))
    {
        if (1 == sscanf(line, "%c", &c))
        {
            if (c == 'y' || c == 'Y')
            {
                fprintf(stdout, "Do you wish to encrypt? (y/n) ");

                if (fgets(line, sizeof(line), stdin))
                {
                    if (1 == sscanf(line, "%c", &c))
                    {
                        if (c == 'y' || c == 'Y')
                        {
                            fprintf(stdout, "Enter passphrase: ");
                            if (fgets(line, sizeof(line), stdin))
                            {
                                char key[50];
                                if (1 == sscanf(line, "%50s", key))
                                {
                                    *passphrase = strdup(key);
                                    *encrypt = 0;
                                }
                                else
                                {
                                    *encrypt = 1;
                                    *passphrase = NULL;
                                }
                            }
                            else
                            {
                                *encrypt = 1;
                                *passphrase = NULL;
                            }
                            return 0;
                        }
                        else
                        {
                            *encrypt = 1;
                            *passphrase = NULL;
                            return 0;
                        }
                    }
                    else
                    {
                        *encrypt = 1;
                        *passphrase = NULL;
                        return 0;
                    }
                }
                else
                {
                    *encrypt = 1;
                    *passphrase = NULL;
                    return 0;
                }
            }
            else
            {
                *encrypt = 1;
                *passphrase = NULL;
                return 1;
            }
        }
        else
        {
            *encrypt = 1;
            *passphrase = NULL;
            return 1;
        }
    }
    else
    {
        *encrypt = 1;
        *passphrase = NULL;
        return 1;
    }
}