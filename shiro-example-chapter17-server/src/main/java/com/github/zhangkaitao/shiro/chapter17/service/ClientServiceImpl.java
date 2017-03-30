package com.github.zhangkaitao.shiro.chapter17.service;

import com.github.zhangkaitao.shiro.chapter17.dao.ClientDao;
import com.github.zhangkaitao.shiro.chapter17.entity.Client;
import org.apache.oltu.oauth2.as.issuer.MD5Generator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

/**
 * <p>User: Zhang Kaitao
 * <p>Date: 14-2-17
 * <p>Version: 1.0
 */
@Transactional
@Service
public class ClientServiceImpl implements ClientService {
    @Autowired
    private ClientDao clientDao;


    public Client createClient(Client client) {

        client.setClientId(UUID.randomUUID().toString());
        client.setClientSecret(UUID.randomUUID().toString());
        return clientDao.createClient(client);
    }


    public Client updateClient(Client client) {
        return clientDao.updateClient(client);
    }


    public void deleteClient(Long clientId) {
        clientDao.deleteClient(clientId);
    }


    public Client findOne(Long clientId) {
        return clientDao.findOne(clientId);
    }


    public List<Client> findAll() {
        return clientDao.findAll();
    }


    public Client findByClientId(String clientId) {
        return clientDao.findByClientId(clientId);
    }


    public Client findByClientSecret(String clientSecret) {
        return clientDao.findByClientSecret(clientSecret);
    }
}
