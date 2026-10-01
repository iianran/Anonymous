# Control: dangling reference attached to a plain Add (no mul-conv structure) -> no crash if other passes tolerate it
import tensorflow as tf
from tensorflow.core.framework import graph_pb2, node_def_pb2, tensor_pb2
from tensorflow.core.protobuf import config_pb2, meta_graph_pb2
from tensorflow.python.grappler import tf_optimizer
g = graph_pb2.GraphDef()
def const_node(name, val):
    n = node_def_pb2.NodeDef(); n.name=name; n.op="Const"; n.attr["dtype"].type=1
    t = tensor_pb2.TensorProto(); t.dtype=1; t.tensor_shape.dim.add().size=1
    t.tensor_shape.dim.add().size=1; t.float_val.append(val)
    n.attr["value"].tensor.CopyFrom(t); return n
for i in range(8): g.node.extend([const_node(f"pad{i}", float(i))])
add = node_def_pb2.NodeDef(); add.name="add"; add.op="Add"
add.input.extend(["missing_node_a","pad0"]); add.attr["T"].type=1   # dangling but no mul-conv
g.node.extend([add]); g.versions.producer=27
mg = meta_graph_pb2.MetaGraphDef(); mg.graph_def.CopyFrom(g)
mg.signature_def["poc"].outputs["out"].name = "add:0"
cfg = config_pb2.ConfigProto(); rw = cfg.graph_options.rewrite_options
rw.min_graph_nodes=-1; rw.disable_meta_optimizer=False
out = tf_optimizer.OptimizeGraph(cfg, mg, verbose=False, graph_id=b"poc")
print("control survived:", [(n.name,n.op) for n in out.node][:3])
