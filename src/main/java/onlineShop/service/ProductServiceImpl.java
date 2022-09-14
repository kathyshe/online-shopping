package onlineShop.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import onlineShop.dao.ProductDao;
import onlineShop.model.Product;

@Service
public class ProductServiceImpl implements ProductService { // DAO || service layer || controller layer
															// avoid DAO layer being accessed directly

    @Autowired
    private ProductDao productDao;

    @Override
    public List<Product> getAllProducts() {
   	 return productDao.getAllProducts();
    }

    @Override
    public Product getProductById(int productId) {
   	 return productDao.getProductById(productId);
    }
    
    @Override
    public void deleteProduct(int productId) {
   	 productDao.deleteProduct(productId);
    }
    
    @Override
    public void addProduct(Product product){
   	 productDao.addProduct(product);
    }
    
    @Override
    public void updateProduct(Product product){
   	 productDao.updateProduct(product);
    }
}

