/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2017 Philippe Proulx <pproulx@efficios.com>
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
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

/* Type */
struct bt_notification_iterator;

/* Status */
enum bt_notification_iterator_status {
	BT_NOTIFICATION_ITERATOR_STATUS_CANCELED = 125,
	BT_NOTIFICATION_ITERATOR_STATUS_AGAIN = 11,
	BT_NOTIFICATION_ITERATOR_STATUS_END = 1,
	BT_NOTIFICATION_ITERATOR_STATUS_OK = 0,
	BT_NOTIFICATION_ITERATOR_STATUS_INVALID = -22,
	BT_NOTIFICATION_ITERATOR_STATUS_ERROR = -1,
	BT_NOTIFICATION_ITERATOR_STATUS_NOMEM = -12,
	BT_NOTIFICATION_ITERATOR_STATUS_UNSUPPORTED = -2,
};

/* Functions (private connection) */
struct bt_component *bt_private_connection_notification_iterator_get_component(
		struct bt_notification_iterator *iterator);
enum bt_notification_iterator_status bt_private_connection_notification_iterator_next(
		struct bt_notification_iterator *iterator,
		bt_notification_array *notifs, uint64_t *count);

/* Functions (output port) */
struct bt_notification_iterator *bt_output_port_notification_iterator_create(
		struct bt_port *port, const char *colander_component_name);
enum bt_notification_iterator_status bt_output_port_notification_iterator_next(
		struct bt_notification_iterator *iterator,
		bt_notification_array *notifs, uint64_t *count);

/* Helper functions for Python */
%{
static PyObject *bt_py3_get_user_component_from_user_notif_iter(
		struct bt_private_connection_private_notification_iterator *priv_notif_iter)
{
	struct bt_private_component *priv_comp =
		bt_private_connection_private_notification_iterator_get_private_component(
			priv_notif_iter);
	PyObject *py_comp;

	BT_ASSERT(priv_comp);
	py_comp = bt_private_component_get_user_data(priv_comp);
	bt_put(priv_comp);
	BT_ASSERT(py_comp);

	/* Return new reference */
	Py_INCREF(py_comp);
	return py_comp;
}

static inline
PyObject *create_pylist_from_notifs(bt_notification_array notifs,
		uint64_t notif_count)
{
	uint64_t i;
	PyObject *py_notif_list = Py_None;

	py_notif_list = PyList_New(notif_count);
	BT_ASSERT(py_notif_list);
	for (i = 0; i < notif_count; i++) {
		PyList_SET_ITEM(py_notif_list, i,
				SWIG_NewPointerObj(SWIG_as_voidptr(notifs[i]),
					SWIGTYPE_p_bt_notification, 0));
	}

	return py_notif_list;
}

static PyObject
*bt_py3_private_connection_get_notification_range(
		struct bt_notification_iterator *iter)
{
	PyObject *py_return_tuple;
	PyObject *py_notif_list = Py_None;
	PyObject *py_status;
	bt_notification_array notifs;
	uint64_t notif_count = 0;
	enum bt_notification_iterator_status status;

	status =
		bt_private_connection_notification_iterator_next(iter, &notifs,
				&notif_count);
	py_status = SWIG_From_long_SS_long(status);
	if (status != BT_NOTIFICATION_ITERATOR_STATUS_OK) {
		goto end;
	}

	py_notif_list = create_pylist_from_notifs(notifs, notif_count);

end:
	py_return_tuple = PyTuple_New(2);
	BT_ASSERT(py_return_tuple);
	PyTuple_SET_ITEM(py_return_tuple, 0, py_status);
	PyTuple_SET_ITEM(py_return_tuple, 1, py_notif_list);

	return py_return_tuple;
}

static PyObject
*bt_py3_output_port_get_notification_range(
		struct bt_notification_iterator *iter)
{
	PyObject *py_return_tuple;
	PyObject *py_notif_list = Py_None;
	PyObject *py_status;
	bt_notification_array notifs;
	uint64_t notif_count = 0;
	enum bt_notification_iterator_status status;

	status =
		bt_output_port_notification_iterator_next(iter, &notifs,
				&notif_count);
	py_status = SWIG_From_long_SS_long(status);
	if (status != BT_NOTIFICATION_ITERATOR_STATUS_OK) {
		goto end;
	}

	py_notif_list = create_pylist_from_notifs(notifs, notif_count);

end:
	py_return_tuple = PyTuple_New(2);
	BT_ASSERT(py_return_tuple);
	PyTuple_SET_ITEM(py_return_tuple, 0, py_status);
	PyTuple_SET_ITEM(py_return_tuple, 1, py_notif_list);

	return py_return_tuple;
}
%}

PyObject *bt_py3_get_user_component_from_user_notif_iter(
		struct bt_private_connection_private_notification_iterator *priv_notif_iter);
PyObject *bt_py3_private_connection_get_notification_range(
		struct bt_notification_iterator *iter);
PyObject *bt_py3_output_port_get_notification_range(
		struct bt_notification_iterator *iter);
