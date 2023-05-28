import React from "react";
import { Item } from "../Item";

interface Item {
  id: number;
  name: string;
  price: number;
  category_name: string;
}

interface Prop {
  items: Item[];
}

export const ItemList: React.FC<Prop> = (props) => {
  const chunkSize = 3; // チャンクのサイズ

  if (!props.items) {
    return <div>No items available.</div>;
  }

  // チャンクに分割する関数
  const chunkArray = (array: any[], size: number) => {
    const chunkedArray = [];
    for (let i = 0; i < array.length; i += size) {
      chunkedArray.push(array.slice(i, i + size));
    }
    return chunkedArray;
  };

  const itemChunks = chunkArray(props.items, chunkSize); // アイテムをチャンクに分割

  return (
    <div>
      {itemChunks.map((chunk, index) => (
        <div key={index} style={{ display: "flex" }}>
          {chunk.map((item, itemIndex) => (
            <div key={item.id} style={{ marginRight: "20px" }}>
              <Item item={item} />
            </div>
          ))}
        </div>
      ))}
    </div>
  );
};
