-- Exemplos SQL avançados detectados via AST multi-dialeto (SQLGlot)

DELETE FROM temp_events;

SELECT DISTINCT a.id
FROM analytics.fact_orders a
JOIN analytics.dim_customers b ON a.customer_id = b.customer_id;

SELECT id FROM analytics.orders_2025
UNION
SELECT id FROM analytics.orders_2026;

SELECT order_id, total
FROM analytics.fact_orders
WHERE DATE(created_at) = '2026-01-01';
