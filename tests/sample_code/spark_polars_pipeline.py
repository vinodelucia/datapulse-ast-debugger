"""Exemplos de antipadrões em PySpark, Polars e Python Data Engineering."""

import pickle


def collect_all_driver_oom(spark_df):
    """Traz todo o DataFrame distribuído para o driver sem limit."""
    return spark_df.collect()


def apply_python_udf(df, F):
    """UDF Python força serialização JVM <-> Python por linha."""
    normalize = F.udf(lambda s: s.strip().lower())
    return df.withColumn("clean", normalize(df["name"]))


def iterate_polars_rows(pl_df):
    """Iteração linha a linha quebra vetorização do Polars."""
    out = []
    for row in pl_df.iter_rows():
        out.append(row[0])
    return out


def deserialize_untrusted(payload_bytes: bytes):
    """Desserialização insegura com pickle."""
    return pickle.loads(payload_bytes)


def append_audit_item(item, bucket=[]):
    """Argumento padrão mutável vaza estado entre chamadas."""
    bucket.append(item)
    return bucket
