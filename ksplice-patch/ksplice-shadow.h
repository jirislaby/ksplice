#include <linux/list.h>
#include <linux/gfp.h>
#include "ksplice-patch.h"

struct shadow_field {
	void *obj;
	void *data;
	int *key;
	struct list_head list;
};

LIST_HEAD(shadow_list);
DEFINE_SPINLOCK(shadow_lock);

int init_shadow_field_type(int *shadow_key, typeof(GFP_KERNEL) gfp_flags)
{
	return 0;
}

void *init_shadow_field(int *shadow_key, void *obj, int size,
			typeof(GFP_KERNEL) gfp_flags)
{
	struct shadow_field *shadow = kmalloc(sizeof(*shadow), gfp_flags);
	if (shadow == NULL)
		return NULL;
	shadow->obj = obj;
	shadow->key = shadow_key;
	shadow->data = kmalloc(size, gfp_flags);
	if (shadow->data == NULL) {
		kfree(shadow);
		return NULL;
	}
	spin_lock(&shadow_lock);
	list_add(&shadow->list, &shadow_list);
	spin_unlock(&shadow_lock);
	return shadow->data;
}

void cleanup_shadow_field(int *shadow_key, void *obj)
{
	struct shadow_field *shadow;
	spin_lock(&shadow_lock);
	list_for_each_entry(shadow, &shadow_list, list) {
		if (shadow->obj == obj && shadow->key == shadow_key) {
			list_del(&shadow->list);
			kfree(shadow->data);
			kfree(shadow);
			goto out;
		}
	}
out:
	spin_unlock(&shadow_lock);
}

void *get_shadow_field(int *shadow_key, void *obj)
{
	struct shadow_field *shadow;
	void *data = NULL;
	spin_lock(&shadow_lock);
	list_for_each_entry(shadow, &shadow_list, list) {
		if (shadow->obj == obj && shadow->key == shadow_key) {
			data = shadow->data;
			goto out;
		}
	}
out:
	spin_unlock(&shadow_lock);
	return data;
}

void cleanup_shadow_field_type(int *shadow_key)
{
	struct shadow_field *shadow, *n;
	spin_lock(&shadow_lock);
	list_for_each_entry_safe(shadow, n, &shadow_list, list) {
		if (shadow->key == shadow_key) {
			list_del(&shadow->list);
			kfree(shadow->data);
			kfree(shadow);
		}
	}
	spin_unlock(&shadow_lock);
}
