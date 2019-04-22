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

/* From graph-const.h */

typedef enum bt_graph_status {
	BT_GRAPH_STATUS_OK = 0,
	BT_GRAPH_STATUS_END = 1,
	BT_GRAPH_STATUS_AGAIN = 11,
	BT_GRAPH_STATUS_COMPONENT_REFUSES_PORT_CONNECTION = 111,
	BT_GRAPH_STATUS_CANCELED = 125,
	BT_GRAPH_STATUS_ERROR = -1,
	BT_GRAPH_STATUS_NO_SINK = -6,
	BT_GRAPH_STATUS_NOMEM = -12,
} bt_graph_status;

extern bt_bool bt_graph_is_canceled(const bt_graph *graph);

extern void bt_graph_get_ref(const bt_graph *graph);

extern void bt_graph_put_ref(const bt_graph *graph);

/* From graph.h */

typedef void (*bt_graph_filter_component_input_port_added_listener_func)(
		const bt_component_filter *component,
		const bt_port_input *port, void *data);

typedef void (*bt_graph_sink_component_input_port_added_listener_func)(
		const bt_component_sink *component,
		const bt_port_input *port, void *data);

typedef void (*bt_graph_source_component_output_port_added_listener_func)(
		const bt_component_source *component,
		const bt_port_output *port, void *data);

typedef void (*bt_graph_filter_component_output_port_added_listener_func)(
		const bt_component_filter *component,
		const bt_port_output *port, void *data);

typedef void (*bt_graph_source_filter_component_ports_connected_listener_func)(
		const bt_component_source *source_component,
		const bt_component_filter *filter_component,
		const bt_port_output *upstream_port,
		const bt_port_input *downstream_port, void *data);

typedef void (*bt_graph_source_sink_component_ports_connected_listener_func)(
		const bt_component_source *source_component,
		const bt_component_sink *sink_component,
		const bt_port_output *upstream_port,
		const bt_port_input *downstream_port, void *data);

typedef void (*bt_graph_filter_filter_component_ports_connected_listener_func)(
		const bt_component_filter *filter_component_upstream,
		const bt_component_filter *filter_component_downstream,
		const bt_port_output *upstream_port,
		const bt_port_input *downstream_port,
		void *data);

typedef void (*bt_graph_filter_sink_component_ports_connected_listener_func)(
		const bt_component_filter *filter_component,
		const bt_component_sink *sink_component,
		const bt_port_output *upstream_port,
		const bt_port_input *downstream_port, void *data);

typedef void (* bt_graph_listener_removed_func)(void *data);

extern bt_graph *bt_graph_create(void);

extern bt_graph_status bt_graph_add_source_component(bt_graph *graph,
		const bt_component_class_source *component_class,
		const char *name, const bt_value *params,
		const bt_component_source **component);

extern bt_graph_status bt_graph_add_source_component_with_init_method_data(
		bt_graph *graph,
		const bt_component_class_source *component_class,
		const char *name, const bt_value *params,
		void *init_method_data,
		const bt_component_source **component);

extern bt_graph_status bt_graph_add_filter_component(bt_graph *graph,
		const bt_component_class_filter *component_class,
		const char *name, const bt_value *params,
		const bt_component_filter **component);

extern bt_graph_status bt_graph_add_filter_component_with_init_method_data(
		bt_graph *graph,
		const bt_component_class_filter *component_class,
		const char *name, const bt_value *params,
		void *init_method_data,
		const bt_component_filter **component);

extern bt_graph_status bt_graph_add_sink_component(
		bt_graph *graph, const bt_component_class_sink *component_class,
		const char *name, const bt_value *params,
		const bt_component_sink **component);

extern bt_graph_status bt_graph_add_sink_component_with_init_method_data(
		bt_graph *graph, const bt_component_class_sink *component_class,
		const char *name, const bt_value *params,
		void *init_method_data,
		const bt_component_sink **component);

extern bt_graph_status bt_graph_connect_ports(bt_graph *graph,
		const bt_port_output *upstream,
		const bt_port_input *downstream,
		const bt_connection **connection);

extern bt_graph_status bt_graph_run(bt_graph *graph);

extern bt_graph_status bt_graph_consume(bt_graph *graph);

extern bt_graph_status bt_graph_add_filter_component_input_port_added_listener(
		bt_graph *graph,
		bt_graph_filter_component_input_port_added_listener_func listener,
		bt_graph_listener_removed_func listener_removed, void *data,
		int *listener_id);

extern bt_graph_status bt_graph_add_sink_component_input_port_added_listener(
		bt_graph *graph,
		bt_graph_sink_component_input_port_added_listener_func listener,
		bt_graph_listener_removed_func listener_removed, void *data,
		int *listener_id);

extern bt_graph_status bt_graph_add_source_component_output_port_added_listener(
		bt_graph *graph,
		bt_graph_source_component_output_port_added_listener_func listener,
		bt_graph_listener_removed_func listener_removed, void *data,
		int *listener_id);

extern bt_graph_status bt_graph_add_filter_component_output_port_added_listener(
		bt_graph *graph,
		bt_graph_filter_component_output_port_added_listener_func listener,
		bt_graph_listener_removed_func listener_removed, void *data,
		int *listener_id);

extern bt_graph_status
bt_graph_add_source_filter_component_ports_connected_listener(
		bt_graph *graph,
		bt_graph_source_filter_component_ports_connected_listener_func listener,
		bt_graph_listener_removed_func listener_removed, void *data,
		int *listener_id);

extern bt_graph_status
bt_graph_add_filter_filter_component_ports_connected_listener(
		bt_graph *graph,
		bt_graph_filter_filter_component_ports_connected_listener_func listener,
		bt_graph_listener_removed_func listener_removed, void *data,
		int *listener_id);

extern bt_graph_status
bt_graph_add_source_sink_component_ports_connected_listener(
		bt_graph *graph,
		bt_graph_source_sink_component_ports_connected_listener_func listener,
		bt_graph_listener_removed_func listener_removed, void *data,
		int *listener_id);

extern bt_graph_status
bt_graph_add_filter_sink_component_ports_connected_listener(
		bt_graph *graph,
		bt_graph_filter_sink_component_ports_connected_listener_func listener,
		bt_graph_listener_removed_func listener_removed, void *data,
		int *listener_id);

extern bt_graph_status bt_graph_cancel(bt_graph *graph);

/* Helper functions for Python */

%{

static void graph_listener_removed(void *py_callable)
{
	BT_ASSERT(py_callable);
	Py_DECREF(py_callable);
}

static void
port_added_listener(const bt_component *component, const bt_port *port,
		    bt_port_type port_type, void *py_callable)
{
	PyObject *py_port_ptr = NULL;
	PyObject *py_res = NULL;

	swig_type_info *port_swig_type = NULL;
	switch (port_type) {
	case BT_PORT_TYPE_INPUT:
		port_swig_type = SWIGTYPE_p_bt_port_input;
		break;
	case BT_PORT_TYPE_OUTPUT:
		port_swig_type = SWIGTYPE_p_bt_port_output;
		break;
	}
	BT_ASSERT(port_swig_type != NULL);

	py_port_ptr = SWIG_NewPointerObj(SWIG_as_voidptr(port),
		port_swig_type, 0);
	if (!py_port_ptr) {
		BT_LOGF_STR("Failed to create a SWIG pointer object.");
		abort();
	}

	py_res = PyObject_CallFunction(py_callable, "(Oi)", py_port_ptr, port_type);
	if (!py_res) {
		bt2_py_loge_exception();
		PyErr_Clear();
	} else {
		BT_ASSERT(py_res == Py_None);
	}
	Py_DECREF(py_port_ptr);
	Py_XDECREF(py_res);
}

static void
source_component_output_port_added_listener(const bt_component_source *component_source,
					    const bt_port_output *port_output, void *py_callable)
{
	const bt_component *component = bt_component_source_as_component_const(component_source);
	const bt_port *port = bt_port_output_as_port_const(port_output);
	port_added_listener(component, port, BT_PORT_TYPE_OUTPUT, py_callable);
}

static void
filter_component_input_port_added_listener(const bt_component_filter *component_filter,
					   const bt_port_input *port_input, void *py_callable)
{
	const bt_component *component = bt_component_filter_as_component_const(component_filter);
	const bt_port *port = bt_port_input_as_port_const(port_input);
	port_added_listener(component, port, BT_PORT_TYPE_INPUT, py_callable);
}

static void
filter_component_output_port_added_listener(const bt_component_filter *component_filter,
					    const bt_port_output *port_output, void *py_callable)
{
	const bt_component *component = bt_component_filter_as_component_const(component_filter);
	const bt_port *port = bt_port_output_as_port_const(port_output);
	port_added_listener(component, port, BT_PORT_TYPE_OUTPUT, py_callable);
}

static void
sink_component_input_port_added_listener(const bt_component_sink *component_sink,
					 const bt_port_input *port_input, void *py_callable)
{
	const bt_component *component = bt_component_sink_as_component_const(component_sink);
	const bt_port *port = bt_port_input_as_port_const(port_input);
	port_added_listener(component, port, BT_PORT_TYPE_INPUT, py_callable);
}

static PyObject *
bt_py3_graph_add_port_added_listener(struct bt_graph *graph,
				     PyObject *py_callable)
{
	PyObject *py_listener_ids = NULL;
	PyObject *py_listener_id = NULL;
	int listener_id;
	bt_graph_status status;

	BT_ASSERT(graph);
	BT_ASSERT(py_callable);

	/* Behind the scene, we will be registering 4 different listeners and
	 * return all of their ids. */
	py_listener_ids = PyList_New(4);
	if (!py_listener_ids) {
		goto fail;
	}

	/* source output port */
	status = bt_graph_add_source_component_output_port_added_listener(
		graph, source_component_output_port_added_listener,
		graph_listener_removed, py_callable, &listener_id);
	if (status != BT_GRAPH_STATUS_OK) {
		goto fail;
	}

	py_listener_id = PyLong_FromLong(listener_id);
	if (!py_listener_id) {
		goto fail;
	}

	PyList_SET_ITEM(py_listener_ids, 0, py_listener_id);

	/* filter input port */
	status = bt_graph_add_filter_component_input_port_added_listener(
		graph, filter_component_input_port_added_listener,
		graph_listener_removed, py_callable, &listener_id);
	if (status != BT_GRAPH_STATUS_OK) {
		goto fail;
	}

	py_listener_id = PyLong_FromLong(listener_id);
	if (!py_listener_id) {
		goto fail;
	}

	PyList_SET_ITEM(py_listener_ids, 1, py_listener_id);

	/* filter output port */
	status = bt_graph_add_filter_component_output_port_added_listener(
		graph, filter_component_output_port_added_listener,
		graph_listener_removed, py_callable, &listener_id);
	if (status != BT_GRAPH_STATUS_OK) {
		goto fail;
	}

	py_listener_id = PyLong_FromLong(listener_id);
	if (!py_listener_id) {
		goto fail;
	}

	PyList_SET_ITEM(py_listener_ids, 2, py_listener_id);

	/* sink input port */
	status = bt_graph_add_sink_component_input_port_added_listener(
		graph, sink_component_input_port_added_listener,
		graph_listener_removed, py_callable, &listener_id);
	if (status != BT_GRAPH_STATUS_OK) {
		goto fail;
	}

	py_listener_id = PyLong_FromLong(listener_id);
	if (!py_listener_id) {
		goto fail;
	}


	PyList_SET_ITEM(py_listener_ids, 3, py_listener_id);

	Py_INCREF(py_callable);
	Py_INCREF(py_callable);
	Py_INCREF(py_callable);
	Py_INCREF(py_callable);

	return py_listener_ids;

fail:
	// TODO: undo ?
	Py_RETURN_NONE;
}

static void
ports_connected_listener(const bt_port_output *upstream_port,
			 const bt_port_input *downstream_port,
			 void *py_callable)
{
	PyObject *py_upstream_port_ptr = NULL;
	PyObject *py_downstream_port_ptr = NULL;
	PyObject *py_res = NULL;

	py_upstream_port_ptr = SWIG_NewPointerObj(
		SWIG_as_voidptr(upstream_port), SWIGTYPE_p_bt_port_output, 0);
	if (!py_upstream_port_ptr) {
		BT_LOGF_STR("Failed to create a SWIG pointer object.");
		abort();
	}

	py_downstream_port_ptr = SWIG_NewPointerObj(
		SWIG_as_voidptr(downstream_port), SWIGTYPE_p_bt_port_input, 0);
	if (!py_downstream_port_ptr) {
		BT_LOGF_STR("Failed to create a SWIG pointer object.");
		abort();
	}

	py_res = PyObject_CallFunction(py_callable, "(OO)",
		py_upstream_port_ptr, py_downstream_port_ptr);
	if (!py_res) {
		bt2_py_loge_exception();
		PyErr_Clear();
	} else {
		BT_ASSERT(py_res == Py_None);
	}

	Py_DECREF(py_upstream_port_ptr);
	Py_DECREF(py_downstream_port_ptr);
	Py_XDECREF(py_res);
}

static void
source_filter_component_ports_connected_listener(
	const bt_component_source *source_component,
	const bt_component_filter *filter_component,
	const bt_port_output *upstream_port,
	const bt_port_input *downstream_port, void *py_callable)
{
	ports_connected_listener(upstream_port, downstream_port, py_callable);
}

static void
source_sink_component_ports_connected_listener(
	const bt_component_source *source_component,
	const bt_component_sink *sink_component,
	const bt_port_output *upstream_port,
	const bt_port_input *downstream_port, void *py_callable)
{
	ports_connected_listener(upstream_port, downstream_port, py_callable);
}

static void
filter_filter_component_ports_connected_listener(
	const bt_component_filter *filter_component_left,
	const bt_component_filter *filter_component_right,
	const bt_port_output *upstream_port,
	const bt_port_input *downstream_port, void *py_callable)
{
	ports_connected_listener(upstream_port, downstream_port, py_callable);
}

static void
filter_sink_component_ports_connected_listener(
	const bt_component_filter *filter_component,
	const bt_component_sink *sink_component,
	const bt_port_output *upstream_port,
	const bt_port_input *downstream_port, void *py_callable)
{
	ports_connected_listener(upstream_port, downstream_port, py_callable);
}


static PyObject*
bt_py3_graph_add_ports_connected_listener(struct bt_graph *graph,
	PyObject *py_callable)
{
	PyObject *py_listener_ids = NULL;
	PyObject *py_listener_id = NULL;
	int listener_id;
	bt_graph_status status;

	BT_ASSERT(graph);
	BT_ASSERT(py_callable);

	/* Behind the scene, we will be registering 4 different listeners and
	 * return all of their ids. */
	py_listener_ids = PyList_New(4);
	if (!py_listener_ids) {
		goto fail;
	}

	/* source -> filter connection */
	status = bt_graph_add_source_filter_component_ports_connected_listener(
		graph, source_filter_component_ports_connected_listener,
		graph_listener_removed, py_callable, &listener_id);
	if (status != BT_GRAPH_STATUS_OK) {
		goto fail;
	}

	py_listener_id = PyLong_FromLong(listener_id);
	if (!py_listener_id) {
		goto fail;
	}

	PyList_SET_ITEM(py_listener_ids, 0, py_listener_id);

	/* source -> sink connection */
	status = bt_graph_add_source_sink_component_ports_connected_listener(
		graph, source_sink_component_ports_connected_listener,
		graph_listener_removed, py_callable, &listener_id);
	if (status != BT_GRAPH_STATUS_OK) {
		goto fail;
	}

	py_listener_id = PyLong_FromLong(listener_id);
	if (!py_listener_id) {
		goto fail;
	}

	PyList_SET_ITEM(py_listener_ids, 1, py_listener_id);

	/* filter -> filter connection */
	status = bt_graph_add_filter_filter_component_ports_connected_listener(
		graph, filter_filter_component_ports_connected_listener,
		graph_listener_removed, py_callable, &listener_id);
	if (status != BT_GRAPH_STATUS_OK) {
		goto fail;
	}

	py_listener_id = PyLong_FromLong(listener_id);
	if (!py_listener_id) {
		goto fail;
	}

	PyList_SET_ITEM(py_listener_ids, 2, py_listener_id);

	/* filter -> sink connection */
	status = bt_graph_add_filter_sink_component_ports_connected_listener(
		graph, filter_sink_component_ports_connected_listener,
		graph_listener_removed, py_callable, &listener_id);
	if (status != BT_GRAPH_STATUS_OK) {
		goto fail;
	}

	py_listener_id = PyLong_FromLong(listener_id);
	if (!py_listener_id) {
		goto fail;
	}


	PyList_SET_ITEM(py_listener_ids, 3, py_listener_id);

	Py_INCREF(py_callable);
	Py_INCREF(py_callable);
	Py_INCREF(py_callable);
	Py_INCREF(py_callable);

	return py_listener_ids;

fail:
	Py_RETURN_NONE;
}

%}

PyObject *bt_py3_graph_add_port_added_listener(struct bt_graph *graph,
		PyObject *py_callable);
PyObject *bt_py3_graph_add_ports_connected_listener(struct bt_graph *graph,
		PyObject *py_callable);
