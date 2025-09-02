import pandas as pd
df = pd.DataFrame({
    "Product":["Mango","Corn","Orange","Cabbage","Mango","Corn","Watermelon","Apple","Pumpkin","Mango"],
    "Category":["Fruit","Vegetable","Fruit","Vegetable","Fruit","Vegetable","Fruit","Fruit","Vegetable","Fruit"],
    "Qty":[10,20,40,25,100,35,85,81,20,90],
    "Price":[10,20,40,25,100,35,85,81,20,90],
})
#print(df)
#print(df.groupby("Product").sum())
#print(df.groupby("Category").sum())
#print(df.groupby("Category")["Price"].mean())
tot_sales = df.pivot_table(index="Category",
                           values="Price",
                           aggfunc={"min","max","mean","median"})
print(tot_sales)
print(df.describe())