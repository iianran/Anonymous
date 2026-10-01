# Control (3): dangling input attached to mul's own child (the side already fixed by CVE-2022-23589) -> should not crash
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
# all conv inputs are valid
conv = node_def_pb2.NodeDef(); conv.name="conv"; conv.op="Conv2D"
conv.input.extend(["pad0","pad1"])
conv.attr["T"].type=1; conv.attr["strides"].list.i.extend([1,1,1,1])
conv.attr["padding"].s=b"SAME"; conv.attr["data_format"].s=b"NHWC"
conv.attr["dilations"].list.i.extend([1,1,1,1])
g.node.extend([conv])
mul = node_def_pb2.NodeDef(); mul.name="mul"; mul.op="Mul"
mul.input.extend(["missing_node_a","conv"])   # <- dangling on the MUL child (fixed side)
mul.attr["T"].type=1
g.node.extend([mul]); g.versions.producer=27
mg = meta_graph_pb2.MetaGraphDef(); mg.graph_def.CopyFrom(g)
mg.signature_def["poc"].outputs["out"].name = "mul:0"
cfg = config_pb2.ConfigProto(); rw = cfg.graph_options.rewrite_options
rw.min_graph_nodes=-1; rw.disable_meta_optimizer=False
out = tf_optimizer.OptimizeGraph(cfg, mg, verbose=False, graph_id=b"poc")
print("mul-side dangling control survived:", [(n.name,n.op) for n in out.node][:3])
