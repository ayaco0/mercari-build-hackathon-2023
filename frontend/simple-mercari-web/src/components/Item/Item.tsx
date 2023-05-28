import { useState, useEffect } from "react";
import { useCookies } from "react-cookie";
import { useNavigate } from "react-router-dom";
import { fetcherBlob } from "../../helper";



interface Item {
  id: number;
  name: string;
  price: number;
  category_name: string;
  soldOut: boolean;
}

export const Item: React.FC<{ item: Item }> = ({ item }) => {
  const navigate = useNavigate();
  const [itemImage, setItemImage] = useState<string>("");
  const [cookies] = useCookies(["token"]);
  const [soldOut, setSoldOut] = useState(false);


  async function getItemImage(itemId: number): Promise<Blob> {
    return await fetcherBlob(`/items/${itemId}/image`, {
      method: "GET",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        Authorization: `Bearer ${cookies.token}`,
      },
    });
  }

  useEffect(() => {
    async function fetchData() {
      const image = await getItemImage(item.id);
      setItemImage(URL.createObjectURL(image));
    }

    fetchData();
  }, [item]);

  useEffect(() => {
    async function fetchSoldOutStatus() {
      try {
        const response = await fetch(`/items/${item.id}/soldout`, {
          method: "GET",
          headers: {
            "Content-Type": "application/json",
            Accept: "application/json",
            Authorization: `Bearer ${cookies.token}`,
          },
        });
  
        if (response.status ==200) {
          setSoldOut(true);
        }
      } catch (error) {
        console.error("Error fetching soldOut status:", error);
      }
    }
  
    fetchSoldOutStatus();
  }, [item, cookies.token]);
  

  return (
    <div>
      <h3>{item.name} {item.soldOut && "(SoldOut)"}
      </h3>
      <img
        src={itemImage}
        alt={item.name}
        height={480}
        width={480}
        onClick={() => navigate(`/item/${item.id}`)}
      />
      {item.soldOut && <span className="soldOut">Sold Out</span>}
      <p>
        <span>Category: {item.category_name}</span>
        <br />
        <span>Price: {item.price}</span>
        <br />
      </p>
    </div>
  );
};



