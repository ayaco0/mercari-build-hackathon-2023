import React, { useEffect, useState } from "react";
import { useCookies } from "react-cookie";
import { MerComponent } from "../MerComponent";
import { toast } from "react-toastify";
import { fetcher } from "../../helper";

interface Category {
  id: number;
  name: string;
}

type formDataType = {
  name: string;
  category_id: number;
  price: number;
  description: string;
  image: string | File;
};

export const Listing: React.FC = () => {
  const initialState = {
    name: "",
    category_id: 1,
    price: 0,
    description: "",
    image: "",
  };
  const [values, setValues] = useState<formDataType>(initialState);
  const [categories, setCategories] = useState<Category[]>([]);
  const [cookies] = useCookies(["token", "userID"]);
  const [suggestedCategory, setSuggestedCategory] = useState<string>("");

  const onValueChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    setValues({
      ...values,
      [event.target.name]: event.target.value,
    });
  };

  const onSelectChange = (event: React.ChangeEvent<HTMLSelectElement>) => {
    setValues({
      ...values,
      [event.target.name]: event.target.value,
    });
  };

  const onFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    setValues({
      ...values,
      [event.target.name]: event.target.files![0],
    });
  };

  const onSubmit = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const data = new FormData();
    data.append("name", values.name);
    data.append("category_id", values.category_id.toString());
    data.append("price", values.price.toString());
    data.append("description", values.description);
    data.append("image", values.image);

    fetcher<{ id: number }>(`/items`, {
      method: "POST",
      body: data,
      headers: {
        Authorization: `Bearer ${cookies.token}`,
      },
    })
      .then((res) => {
        sell(res.id);
      })
      .catch((error: Error) => {
        toast.error(error.message);
        console.error("POST error:", error);
      });
  };

  const sell = (itemID: number) =>
    fetcher(`/sell`, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        Authorization: `Bearer ${cookies.token}`,
      },
      body: JSON.stringify({
        item_id: itemID,
      }),
    })
      .then((_) => {
        toast.success("Item added successfully!");
      })
      .catch((error: Error) => {
        toast.error(error.message);
        console.error("POST error:", error);
      });

  const fetchCategories = () => {
    fetcher<Category[]>(`/items/categories`, {
      method: "GET",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
    })
      .then((items) => setCategories(items))
      .catch((err) => {
        console.log(`GET error:`, err);
        toast.error(err.message);
      });
  };

  const suggestCategory = () => {
    // 「Suggest category」ボタンがクリックされたときに実行される関数
    const text = values.name;

    // クエリパラメータを含んだURLを作成
    const url = `http://127.0.0.1:9000/suggest?text=${encodeURIComponent(text)}`;

    // バックエンドのAPIを呼び出してカテゴリを取得
    fetch(url)
      .then((response) => response.json())
      .then((data) => {
        setSuggestedCategory(data.category);
      })
      .catch((error) => {
        toast.error("Failed to suggest category");
        console.error("GET error:", error);
      });
  };

  useEffect(() => {
    fetchCategories();
  }, []);

  return (
    <MerComponent>
      <div className="Listing">
        <form onSubmit={onSubmit} className="ListingForm">
          <div>
            <input
              type="text"
              name="name"
              id="MerTextInput"
              placeholder="name"
              onChange={onValueChange}
              required
            />
            <button type="button" onClick={suggestCategory} id="MerButton">
              Suggest category
            </button>
            <p>Suggested Category: {suggestedCategory}</p>
            <select
              name="category_id"
              id="MerTextInput"
              // value={values.category_id}
              onChange={onSelectChange}
            >
           
                <option value=""disabled selected>category (選択してください)</option>
            

              {categories &&
                categories.map((category) => {
                  return <option value={category.id}>{category.name}</option>;
                })}
            </select>
            <input
              type="number"
              name="price"
              id="MerTextInput"
              placeholder="price"
              onChange={onValueChange}
              required
            />
            <input
              type="text"
              name="description"
              id="MerTextInput"
              placeholder="description"
              onChange={onValueChange}
              required
            />
            <input
              type="file"
              name="image"
              id="MerTextInput2"
              onChange={onFileChange}
              required
            />
            <button type="submit" id="MerButton">
              List this item
            </button>
          </div>
        </form>
      </div>
    </MerComponent>
  );

};
