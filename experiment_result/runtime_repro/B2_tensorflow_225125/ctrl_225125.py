import tensorflow as tf, sys
pw = int(sys.argv[1])
data = tf.constant(["abc"], dtype=tf.string)
splits = tf.constant([0, 1], dtype=tf.int32)
out = tf.raw_ops.StringNGrams(
    data=data, data_splits=splits, separator=" ", ngram_widths=[],
    left_pad="", right_pad="", pad_width=pw, preserve_short_sequences=True)
print(f"pad_width={pw} survived:", out.numpy() if hasattr(out,'numpy') else out)
