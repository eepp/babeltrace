/*
 * query.c
 *
 * Babeltrace CTF file system Reader Component queries
 *
 * Copyright 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "query.h"
#include <stdbool.h>
#include <babeltrace/assert-internal.h>
#include "metadata.h"
#include "../common/metadata/decoder.h"
#include <babeltrace/common-internal.h>
#include <babeltrace/babeltrace-internal.h>
#include <babeltrace/babeltrace.h>
#include "fs.h"

#define BT_LOG_TAG "PLUGIN-CTF-FS-QUERY-SRC"
#include "logging.h"

#define METADATA_TEXT_SIG	"/* CTF 1.8"

struct range {
	int64_t begin_ns;
	int64_t end_ns;
	bool set;
};

BT_HIDDEN
bt_query_status metadata_info_query(
		bt_self_component_class_source *comp_class,
		const bt_value *params,
		const bt_value **user_result)
{
	bt_query_status status = BT_QUERY_STATUS_OK;
	bt_value *result = NULL;
	const bt_value *path_value = NULL;
	char *metadata_text = NULL;
	FILE *metadata_fp = NULL;
	GString *g_metadata_text = NULL;
	int ret;
	int bo;
	const char *path;
	bool is_packetized;

	result = bt_value_map_create();
	if (!result) {
		status = BT_QUERY_STATUS_NOMEM;
		goto error;
	}

	BT_ASSERT(params);

	if (!bt_value_is_map(params)) {
		BT_LOGE_STR("Query parameters is not a map value object.");
		status = BT_QUERY_STATUS_INVALID_PARAMS;
		goto error;
	}

	path_value = bt_value_map_borrow_entry_value_const(params, "path");
	path = bt_value_string_get(path_value);

	BT_ASSERT(path);
	metadata_fp = ctf_fs_metadata_open_file(path);
	if (!metadata_fp) {
		BT_LOGE("Cannot open trace metadata: path=\"%s\".", path);
		goto error;
	}

	is_packetized = ctf_metadata_decoder_is_packetized(metadata_fp,
		&bo);

	if (is_packetized) {
		ret = ctf_metadata_decoder_packetized_file_stream_to_buf(
			metadata_fp, &metadata_text, bo);
		if (ret) {
			BT_LOGE("Cannot decode packetized metadata file: path=\"%s\"",
				path);
			goto error;
		}
	} else {
		long filesize;

		ret = fseek(metadata_fp, 0, SEEK_END);
		if (ret) {
			BT_LOGE_ERRNO("Failed to seek to the end of the metadata file",
				": path=\"%s\"", path);
			goto error;
		}
		filesize = ftell(metadata_fp);
		if (filesize < 0) {
			BT_LOGE_ERRNO("Failed to get the current position in the metadata file",
				": path=\"%s\"", path);
			goto error;
		}
		rewind(metadata_fp);
		metadata_text = malloc(filesize + 1);
		if (!metadata_text) {
			BT_LOGE_STR("Cannot allocate buffer for metadata text.");
			goto error;
		}

		if (fread(metadata_text, filesize, 1, metadata_fp) != 1) {
			BT_LOGE_ERRNO("Cannot read metadata file", ": path=\"%s\"",
				path);
			goto error;
		}

		metadata_text[filesize] = '\0';
	}

	g_metadata_text = g_string_new(NULL);
	if (!g_metadata_text) {
		goto error;
	}

	if (strncmp(metadata_text, METADATA_TEXT_SIG,
			sizeof(METADATA_TEXT_SIG) - 1) != 0) {
		g_string_assign(g_metadata_text, METADATA_TEXT_SIG);
		g_string_append(g_metadata_text, " */\n\n");
	}

	g_string_append(g_metadata_text, metadata_text);

	ret = bt_value_map_insert_string_entry(result, "text",
		g_metadata_text->str);
	if (ret) {
		BT_LOGE_STR("Cannot insert metadata text into query result.");
		goto error;
	}

	ret = bt_value_map_insert_bool_entry(result, "is-packetized",
		is_packetized);
	if (ret) {
		BT_LOGE_STR("Cannot insert \"is-packetized\" attribute into query result.");
		goto error;
	}

	goto end;

error:
	BT_VALUE_PUT_REF_AND_RESET(result);
	result = NULL;

	if (status >= 0) {
		status = BT_QUERY_STATUS_ERROR;
	}

end:
	free(metadata_text);

	if (g_metadata_text) {
		g_string_free(g_metadata_text, TRUE);
	}

	if (metadata_fp) {
		fclose(metadata_fp);
	}

	*user_result = result;
	return status;
}

static
int add_range(bt_value *info, struct range *range,
		const char *range_name)
{
	int ret = 0;
	bt_value_status status;
	bt_value *range_map = NULL;

	if (!range->set) {
		/* Not an error. */
		goto end;
	}

	range_map = bt_value_map_create();
	if (!range_map) {
		ret = -1;
		goto end;
	}

	status = bt_value_map_insert_integer_entry(range_map, "begin",
			range->begin_ns);
	if (status != BT_VALUE_STATUS_OK) {
		ret = -1;
		goto end;
	}

	status = bt_value_map_insert_integer_entry(range_map, "end",
			range->end_ns);
	if (status != BT_VALUE_STATUS_OK) {
		ret = -1;
		goto end;
	}

	status = bt_value_map_insert_entry(info, range_name,
		range_map);
	if (status != BT_VALUE_STATUS_OK) {
		ret = -1;
		goto end;
	}

end:
	bt_value_put_ref(range_map);
	return ret;
}

static
int add_stream_ids(bt_value *info, struct ctf_fs_ds_file_group *ds_file_group)
{
	int ret = 0;
	bt_value_status status;

	if (ds_file_group->stream_id != UINT64_C(-1)) {
		status = bt_value_map_insert_integer_entry(info, "id",
			(int64_t) ds_file_group->stream_id);
		if (status != BT_VALUE_STATUS_OK) {
			ret = -1;
			goto end;
		}
	}

	status = bt_value_map_insert_integer_entry(info, "class-id",
		(int64_t) ds_file_group->sc->id);
	if (status != BT_VALUE_STATUS_OK) {
		ret = -1;
		goto end;
	}

end:
	return ret;
}

static
int populate_stream_info(struct ctf_fs_ds_file_group *group,
		bt_value *group_info, struct range *stream_range)
{
	int ret = 0;
	size_t file_idx;
	bt_value_status status;
	bt_value *file_paths;

	stream_range->begin_ns = INT64_MAX;
	stream_range->end_ns = 0;

	file_paths = bt_value_array_create();
	if (!file_paths) {
		ret = -1;
		goto end;
	}

	for (file_idx = 0; file_idx < group->ds_file_infos->len; file_idx++) {
		int64_t file_begin_epoch, file_end_epoch;
		struct ctf_fs_ds_file_info *info =
			g_ptr_array_index(group->ds_file_infos,
				file_idx);

		if (!info->index || info->index->entries->len == 0) {
			BT_LOGW("Cannot determine range of unindexed stream file \'%s\'",
				info->path->str);
			ret = -1;
			goto end;
		}

		status = bt_value_array_append_string_element(file_paths,
				info->path->str);
		if (status != BT_VALUE_STATUS_OK) {
			ret = -1;
			goto end;
		}

		/*
		 * file range is from timestamp_begin of the first entry to the
		 * timestamp_end of the last entry.
		 */
		file_begin_epoch = ((struct ctf_fs_ds_index_entry *) &g_array_index(info->index->entries,
				struct ctf_fs_ds_index_entry, 0))->timestamp_begin_ns;
		file_end_epoch = ((struct ctf_fs_ds_index_entry *) &g_array_index(info->index->entries,
				struct ctf_fs_ds_index_entry, info->index->entries->len - 1))->timestamp_end_ns;

		stream_range->begin_ns = min(stream_range->begin_ns, file_begin_epoch);
		stream_range->end_ns = max(stream_range->end_ns, file_end_epoch);
		stream_range->set = true;
	}

	if (stream_range->set) {
		ret = add_range(group_info, stream_range, "range-ns");
		if (ret) {
			goto end;
		}
	}

	status = bt_value_map_insert_entry(group_info, "paths",
		file_paths);
	if (status != BT_VALUE_STATUS_OK) {
		ret = -1;
		goto end;
	}

	ret = add_stream_ids(group_info, group);
	if (ret) {
		goto end;
	}
end:
	bt_value_put_ref(file_paths);
	return ret;
}

static
int populate_trace_info(const struct ctf_fs_trace *trace, bt_value *trace_info)
{
	int ret = 0;
	size_t group_idx;
	bt_value_status status;
	bt_value *file_groups = NULL;
	struct range trace_range = {
		.begin_ns = INT64_MAX,
		.end_ns = 0,
		.set = false,
	};
	struct range trace_intersection = {
		.begin_ns = 0,
		.end_ns = INT64_MAX,
		.set = false,
	};

	BT_ASSERT(trace->ds_file_groups);
	/* Add trace range info only if it contains streams. */
	if (trace->ds_file_groups->len == 0) {
		ret = -1;
		goto end;
	}

	file_groups = bt_value_array_create();
	if (!file_groups) {
		goto end;
	}

	status = bt_value_map_insert_string_entry(trace_info, "name",
		trace->name->str);
	if (status != BT_VALUE_STATUS_OK) {
		ret = -1;
		goto end;
	}
	status = bt_value_map_insert_string_entry(trace_info, "path",
		trace->path->str);
	if (status != BT_VALUE_STATUS_OK) {
		ret = -1;
		goto end;
	}

	/* Find range of all stream groups, and of the trace. */
	for (group_idx = 0; group_idx < trace->ds_file_groups->len;
			group_idx++) {
		bt_value *group_info;
		struct range group_range = { .set = false };
		struct ctf_fs_ds_file_group *group = g_ptr_array_index(
				trace->ds_file_groups, group_idx);

		group_info = bt_value_map_create();
		if (!group_info) {
			ret = -1;
			goto end;
		}

		ret = populate_stream_info(group, group_info, &group_range);
		if (ret) {
			bt_value_put_ref(group_info);
			goto end;
		}

		if (group_range.set) {
			trace_range.begin_ns = min(trace_range.begin_ns,
					group_range.begin_ns);
			trace_range.end_ns = max(trace_range.end_ns,
					group_range.end_ns);
			trace_range.set = true;

			trace_intersection.begin_ns = max(trace_intersection.begin_ns,
					group_range.begin_ns);
			trace_intersection.end_ns = min(trace_intersection.end_ns,
					group_range.end_ns);
			trace_intersection.set = true;
			status = bt_value_array_append_element(
				file_groups,
				group_info);
			bt_value_put_ref(group_info);
			if (status != BT_VALUE_STATUS_OK) {
				goto end;
			}
		}
	}

	ret = add_range(trace_info, &trace_range, "range-ns");
	if (ret) {
		goto end;
	}

	if (trace_intersection.begin_ns < trace_intersection.end_ns) {
		ret = add_range(trace_info, &trace_intersection,
				"intersection-range-ns");
		if (ret) {
			goto end;
		}
	}

	status = bt_value_map_insert_entry(trace_info, "streams",
		file_groups);
	BT_VALUE_PUT_REF_AND_RESET(file_groups);
	if (status != BT_VALUE_STATUS_OK) {
		ret = -1;
		goto end;
	}

end:
	bt_value_put_ref(file_groups);
	return ret;
}

BT_HIDDEN
bt_query_status trace_info_query(
		bt_self_component_class_source *comp_class,
		const bt_value *params,
		const bt_value **user_result)
{
	struct ctf_fs_component *ctf_fs = NULL;
	bt_query_status status = BT_QUERY_STATUS_OK;
	bt_value *result = NULL;
	const bt_value *paths_value = NULL;
	int ret = 0;
	guint i;

	BT_ASSERT(params);

	if (!bt_value_is_map(params)) {
		BT_LOGE("Query parameters is not a map value object.");
		status = BT_QUERY_STATUS_INVALID_PARAMS;
		goto error;
	}

	paths_value = bt_value_map_borrow_entry_value_const(params, "paths");
	if (!validate_paths_parameter(paths_value)) {
		goto error;
	}

	ctf_fs = ctf_fs_component_create();
	if (!ctf_fs) {
		goto error;
	}

	if (ctf_fs_component_create_ctf_fs_traces(NULL, ctf_fs, paths_value)) {
		goto error;
	}

	result = bt_value_array_create();
	if (!result) {
		status = BT_QUERY_STATUS_NOMEM;
		goto error;
	}

	for (i = 0; i < ctf_fs->traces->len; i++) {
		struct ctf_fs_trace *trace;
		bt_value *trace_info;
		bt_value_status status;

		trace = g_ptr_array_index(ctf_fs->traces, i);
		BT_ASSERT(trace);

		trace_info = bt_value_map_create();
		if (!trace_info) {
			BT_LOGE("Failed to create trace info map.");
			goto error;
		}

		ret = populate_trace_info(trace, trace_info);
		if (ret) {
			bt_value_put_ref(trace_info);
			goto error;
		}

		status = bt_value_array_append_element(result, trace_info);
		bt_value_put_ref(trace_info);
		if (status != BT_VALUE_STATUS_OK) {
			goto error;
		}
	}

	goto end;

error:
	BT_VALUE_PUT_REF_AND_RESET(result);
	result = NULL;

	if (status >= 0) {
		status = BT_QUERY_STATUS_ERROR;
	}

end:
	if (ctf_fs) {
		ctf_fs_destroy(ctf_fs);
		ctf_fs = NULL;
	}

	*user_result = result;
	return status;
}
