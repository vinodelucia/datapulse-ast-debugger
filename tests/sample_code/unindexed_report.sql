-- Exemplo de Query Analítica com Problemas de Performance (Full Table Scan & Cross Join)

SELECT *
FROM analytics.fact_orders o
CROSS JOIN analytics.dim_customers c
WHERE o.customer_email LIKE '%@enterprise.com';
