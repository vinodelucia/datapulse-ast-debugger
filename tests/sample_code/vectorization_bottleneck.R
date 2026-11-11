# Exemplo de Script R com Alocação Quadrática de Memória (Falta de Vetorização)

normalize_metrics <- function(df) {
  result <- data.frame()
  for (i in 1:nrow(df)) {
    row_val <- df[i, "value"]
    z_score <- (row_val - mean(df$value)) / sd(df$value)
    result <- rbind(result, data.frame(id = df[i, "id"], z_score = z_score))
  }
  return(result)
}
