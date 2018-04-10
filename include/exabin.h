#ifndef EXABIN_H
#define EXABIN_H

struct binmeta_s;
typedef struct binmeta_s BinMeta;

int parse_args(int argc, char** argv);
void printusage(char *, char *);
int check_deps();
Elf *open_elf_file(char *, int *);
void close_elf_file(int fd, Elf *);
EXBFileData* print_elf_info(Elf *);
double my_log2(double n);
double calc_entropy(char*);
char** print_dynamic_section_contents(Elf *elf, Elf_Scn *scn, GElf_Shdr *shdr, size_t*);
EXBFileSectionMeta* print_section_meta(Elf *elf_file, Elf_Scn *section, GElf_Shdr *scn_hdr, int sh_str_i);

int prompt_to_save(int*, char**);

#endif