#include <bfd.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BITS_PER_LONG LONG_BIT
#define _PASTE(x, y) x##y
#define PASTE(x, y) _PASTE(x, y)

#define DIE do { fprintf(stderr, "ksplice: died at %s:%d\n", __FILE__, __LINE__); abort(); } while(0)
#define assert(x) do { if(!(x)) DIE; } while(0)
#define align(x, n) ((((x)+(n)-1)/(n))*(n))

#define container_of(ptr, type, member) ({			\
	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
	(type *)( (char *)__mptr - offsetof(type,member) );})

#define DECLARE_VEC_TYPE(elt_t, vectype)	\
	struct vectype {			\
		elt_t *data;			\
		size_t size;			\
		size_t mem_size;		\
	}

/* void vec_init(struct vectype *vec); */
#define vec_init(vec) *(vec) = (typeof(*(vec))) { NULL, 0, 0 }

/* void vec_move(struct vectype *dstvec, struct vectype *srcvec); */
#define vec_move(dstvec, srcvec) do {			\
		typeof(srcvec) _srcvec = (srcvec);	\
		*(dstvec) = *(_srcvec);			\
		vec_init(_srcvec);			\
	} while (0)

/* void vec_free(struct vectype *vec); */
#define vec_free(vec) do {			\
		typeof(vec) _vec1 = (vec);	\
		free(_vec1->data);		\
		vec_init(_vec1);		\
	} while (0)

void vec_do_reserve(void **data, size_t *mem_size, size_t newsize);

/* void vec_reserve(struct vectype *vec, size_t new_mem_size); */
#define vec_reserve(vec, new_mem_size) do {				\
		typeof(vec) _vec2 = (vec);				\
		vec_do_reserve((void **)&_vec2->data, &_vec2->mem_size,	\
			       (new_mem_size));				\
	} while (0)

/* void vec_resize(struct vectype *vec, size_t new_size); */
#define vec_resize(vec, new_size) do {					\
		typeof(vec) _vec3 = (vec);				\
		_vec3->size = (new_size);				\
		vec_reserve(_vec3, _vec3->size * sizeof(*_vec3->data));	\
	} while (0)

/* elt_t *vec_grow(struct vectype *vec, size_t n); */
#define vec_grow(vec, n) ({				\
		typeof(vec) _vec4 = (vec);		\
		size_t _n = (n);			\
		vec_resize(_vec4, _vec4->size + _n);	\
		_vec4->data + (_vec4->size - _n);	\
	})

DECLARE_VEC_TYPE(void, void_vec);
DECLARE_VEC_TYPE(arelent *, arelentp_vec);
DECLARE_VEC_TYPE(asymbol *, asymbolp_vec);
DECLARE_VEC_TYPE(asymbol **, asymbolpp_vec);

#define DECLARE_HASH_TYPE(elt_t, hashtype,				\
			  hashtype_init, hashtype_free,			\
			  hashtype_lookup)				\
	struct hashtype {						\
		struct bfd_hash_table root;				\
	};								\
									\
	void hashtype_init(struct hashtype *table);			\
	void hashtype_free(struct hashtype *table);			\
	typeof(elt_t) *hashtype_lookup(struct hashtype *table,		\
				       const char *string,		\
				       bfd_boolean create)

#ifndef BFD_HASH_TABLE_HAS_ENTSIZE
#define bfd_hash_table_init(table, newfunc, entry)	\
	bfd_hash_table_init(table, newfunc)
#endif

#define IMPLEMENT_HASH_TYPE(elt_t, hashtype,				\
			    hashtype_init, hashtype_free,		\
			    hashtype_lookup,				\
			    elt_construct)				\
									\
	struct hashtype##_entry {					\
		struct bfd_hash_entry root;				\
		typeof(elt_t) val;					\
	};								\
									\
	static struct bfd_hash_entry *hashtype##_newfunc(		\
	    struct bfd_hash_entry *entry,				\
	    struct bfd_hash_table *table,				\
	    const char *string)						\
	{								\
		if (entry == NULL) {					\
			entry = bfd_hash_allocate(table,		\
			    sizeof(struct hashtype##_entry));		\
			if (entry == NULL)				\
				return entry;				\
		}							\
		entry = bfd_hash_newfunc(entry, table, string);		\
		typeof(elt_t) *v =					\
		    &container_of(entry, struct hashtype##_entry,	\
				  root)->val;				\
		elt_construct(v);					\
		return entry;						\
	};								\
									\
	void hashtype_init(struct hashtype *table)			\
	{								\
		bfd_hash_table_init(&table->root, hashtype##_newfunc,	\
				    sizeof(struct hashtype##_entry));	\
	}								\
									\
	void hashtype_free(struct hashtype *table)			\
	{								\
		bfd_hash_table_free(&table->root);			\
	}								\
									\
	typeof(elt_t) *hashtype_lookup(struct hashtype *table,		\
				       const char *string,		\
				       bfd_boolean create)		\
	{								\
		struct bfd_hash_entry *e =				\
		    bfd_hash_lookup(&table->root, string, create,	\
				    TRUE);				\
		if (create)						\
			assert(e != NULL);				\
		else if (e == NULL)					\
			return NULL;					\
		return &container_of(e, struct hashtype##_entry,	\
				     root)->val;			\
	}								\
									\
	struct eat_trailing_semicolon

#define DEFINE_HASH_TYPE(elt_t, hashtype,				\
			 hashtype_init, hashtype_free,			\
			 hashtype_lookup,				\
			 elt_construct)					\
	DECLARE_HASH_TYPE(elt_t, hashtype, hashtype_init,		\
			  hashtype_free, hashtype_lookup);		\
	IMPLEMENT_HASH_TYPE(elt_t, hashtype, hashtype_init,		\
			    hashtype_free, hashtype_lookup,		\
			    elt_construct);


#ifndef bfd_get_section_size
#define bfd_get_section_size(x) ((x)->_cooked_size)
#endif

DECLARE_HASH_TYPE(arelent *, arelentp_hash, arelentp_hash_init,
		  arelentp_hash_free, arelentp_hash_lookup);
DECLARE_HASH_TYPE(asymbol **, asymbolpp_hash, asymbolpp_hash_init,
		  asymbolpp_hash_free, asymbolpp_hash_lookup);
DECLARE_HASH_TYPE(const char *, string_hash, string_hash_init,
		  string_hash_free, string_hash_lookup);

struct label_map {
	asymbol *csym;
	const char *orig_label;
	const char *label;
	int count;
};
DECLARE_VEC_TYPE(struct label_map, label_map_vec);
DECLARE_HASH_TYPE(struct label_map *, label_mapp_hash, label_mapp_hash_init,
		  label_mapp_hash_free, label_mapp_hash_lookup);

struct entry_point {
	const char *label;
	const char *name;
	long offset;
	asymbol *symbol;
};
DECLARE_VEC_TYPE(struct entry_point, entry_point_vec);

struct span {
	struct supersect *ss;
	asymbol *symbol;
	const char *orig_label;
	const char *label;
	bfd_vma start;
	bfd_vma size;
	bfd_vma contents_size;
	bool keep;
	bool new;
	bool patch;
	bool bugpatch;
	bool datapatch;
	bool precallable;
	struct span *match;
	struct entry_point_vec entry_points;
	struct entry_point_vec pre_entry_points;
	bfd_size_type shift;
};
DECLARE_VEC_TYPE(struct span, span_vec);

struct superbfd {
	bfd *abfd;
	struct asymbolp_vec syms;
	struct supersect *new_supersects;
	struct label_map_vec maps;
	struct label_mapp_hash maps_hash;
	struct asymbolpp_vec new_syms;
	struct asymbolpp_hash csyms;
	struct string_hash callers;
};

enum supersect_type {
	SS_TYPE_TEXT, SS_TYPE_DATA, SS_TYPE_RODATA, SS_TYPE_STRING,
	SS_TYPE_SPECIAL, SS_TYPE_IGNORED, SS_TYPE_KSPLICE, SS_TYPE_EXPORT,
	SS_TYPE_EXIT, SS_TYPE_KSPLICE_CALL, SS_TYPE_KSPLICE_EXTRACT,
	SS_TYPE_BUGTABLE, SS_TYPE_UNKNOWN
};

struct supersect {
	struct superbfd *parent;
	const char *name;
	flagword flags;
	struct void_vec contents;
	int alignment;
	unsigned int entsize;
	struct arelentp_vec relocs;
	struct arelentp_vec new_relocs;
	struct supersect *next;
	struct asymbolp_vec syms;
	struct span_vec spans;
	struct arelentp_hash reloc_hash;
	asymbol *symbol;
	bool keep;
	enum supersect_type type;
	enum supersect_type orig_type;
	bool match_data_early;
};

struct superbfd *fetch_superbfd(bfd *abfd);
struct supersect *fetch_supersect(struct superbfd *sbfd, asection *sect);
struct supersect *new_supersect(struct superbfd *sbfd, const char *name);
void supersect_move(struct supersect *dest_ss, struct supersect *src_ss);

#define sect_grow(ss, n, type)					\
	((type *)sect_do_grow(ss, n, sizeof(type), __alignof__(type)))
void *sect_do_grow(struct supersect *ss, size_t n, size_t size, int alignment);

#define sect_copy(dest_ss, dest, src_ss, src, n)			\
	sect_do_copy(dest_ss, dest, src_ss, src, (n) * sizeof(*(src)))
void sect_do_copy(struct supersect *dest_ss, void *dest,
		  struct supersect *src_ss, const void *src, size_t n);

#define strstarts(str, prefix)				\
	(strncmp(str, prefix, strlen(prefix)) == 0)
#define ends_with(str, suffix)						\
	(strlen(str) >= strlen(suffix) &&				\
	 strcmp(&str[strlen(str) - strlen(suffix)], suffix) == 0)

bfd_vma addr_offset(struct supersect *ss, const void *addr);
bfd_vma reloc_offset(struct supersect *ss, arelent *reloc);
arelent *find_reloc(struct supersect *ss, const void *addr);
bfd_vma read_reloc(struct supersect *ss, const void *addr, size_t size,
		   asymbol **symp);
const void *read_pointer(struct supersect *ss, void *const *addr,
			 struct supersect **ssp);
const char *read_string(struct supersect *ss, const char *const *addr);

#define read_num(ss, addr) ((typeof(*(addr))) \
			    read_reloc(ss, addr, sizeof(*(addr)), NULL))

static inline char *vstrprintf(const char *fmt, va_list ap)
{
	char *str;
	assert(vasprintf(&str, fmt, ap) >= 0);
	return str;
}

static inline char * __attribute__((format (printf, 1, 2)))
strprintf(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	char *str = vstrprintf(fmt, ap);
	va_end(ap);
	return str;
}
