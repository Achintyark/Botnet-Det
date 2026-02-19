from sqlalchemy.orm import Session
from entity.inventory_entity import CategoryEntity
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Replace with your actual database URL
DATABASE_URL = "postgresql://postgres:admin123@localhost:5432/New_Saas"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def verify_category_hierarchy(client_id: str, root_category_id: str):
    db: Session = SessionLocal()
    try:
        # Fetch root category
        root_cat = db.query(CategoryEntity).filter_by(client_id=client_id, id=root_category_id).first()
        if not root_cat:
            print(f"Category '{root_category_id}' not found.")
            return

        # Recursive function to print category tree
        def print_category(cat, level=0):
            indent = "  " * level
            print(f"{indent}- {cat.id} ({cat.name})")
            if cat.sub_categories:
                for sub_id in cat.sub_categories:
                    sub_cat = db.query(CategoryEntity).filter_by(client_id=client_id, id=sub_id).first()
                    if sub_cat:
                        print_category(sub_cat, level + 1)
                    else:
                        print(f"{indent}  - {sub_id} (Not Found!)")
        print(f"Hierarchy under '{root_category_id}':")
        print_category(root_cat)
    finally:
        db.close()

# Run the verification for your root category 'restaurant'
verify_category_hierarchy('saas', 'restaurant')
