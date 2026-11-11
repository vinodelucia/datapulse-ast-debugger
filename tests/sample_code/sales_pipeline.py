import pandas as pd


def process_sales_chunk(df: pd.DataFrame) -> pd.DataFrame:
    """Antipadrão 1: Uso de .iterrows() gerando gargalo severo de CPU e memória."""
    for idx, row in df.iterrows():
        df.loc[idx, "tax"] = row["price"] * 0.15
        df.loc[idx, "net_total"] = row["price"] + df.loc[idx, "tax"]
    return df


def apply_promotional_discount(df: pd.DataFrame) -> pd.DataFrame:
    """Antipadrão 2: Indexação encadeada (SettingWithCopyWarning silencioso)."""
    df[df["status"] == "ACTIVE"]["discount"] = 0.10
    return df


def fetch_customer_transactions(cursor, user_input_id: str):
    """Antipadrão 3: SQL Injection via interpolação direta em f-string."""
    query = f"SELECT * FROM financial_ledger WHERE account_id = '{user_input_id}'"
    cursor.execute(query)
    return cursor.fetchall()
