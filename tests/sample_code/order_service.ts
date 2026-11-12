import { readFileSync } from 'fs';
import * as fs from 'fs';

interface Order {
  id: number;
  total: number;
}

export class OrderService {
  // Bug: I/O síncrono em método de serviço (n/no-sync)
  loadOrders(path: string): Order[] {
    const raw = fs.readFileSync(path, 'utf8');
    return JSON.parse(raw) as Order[];
  }

  // Bug: promise encadeada sem catch (promise/catch-or-return)
  syncOrders(api: { fetchOrders(): Promise<Order[]> }): void {
    api.fetchOrders().then((orders: Order[]) => {
      console.log(orders.length);
    });
  }
}

export const sumTotals = (orders: Order[]): number =>
  orders.reduce((acc, o) => acc + o.total, 0);
