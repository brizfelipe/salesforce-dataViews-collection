import requests
import aiohttp
from datetime import datetime,timedelta
import math
import asyncio
import os


class DataViewsCollection:
    def __init__(
            self,
            authentication_base_url,
            rest_base_url,
            client_id,
            cliente_secret
            ) -> None:
        self.Authentication_base_url = authentication_base_url
        self.REST_base_url = rest_base_url
        self.Client_id = client_id
        self.Cliente_secret = cliente_secret
        self.token = self.create_access_token()
        
    
    def create_access_token(self):
        try:
            end_point = f"{self.Authentication_base_url}/v2/token"
            headers = {
                'Content-type': 'application/json'
            }
            body = { 
                "grant_type" :  "client_credentials" , 
                "client_id" :  self.Client_id, 
                "client_secret" :  self.Cliente_secret
            }
            req = requests.post(
                end_point,
                headers=headers,
                json=body
            )

            token =  req.json()
            token['create_at'] = datetime.now()
            return token
        except Exception as e:
            print(e)
            return False  
        

    def  access_token_expiration_data(self)->datetime:
        """
        The access token JSON contains a key named 'expires_in'
        which represents the validity period of this token in seconds. 
        It also includes another key named 'created_at'
        which is a datetime object. 
        We convert 'expires_in' to a timedelta and add it to 'created_at'. 
        This results in the datetime when the token will expire.

        Args:
            access_token (dict): 
                To obtain this token, you first need to create it using the function.
                {get_access_token}

        Returns:
            datetime: We return the datetime to this token will 
        """
        time_to_token_expires = timedelta(
            minutes=self.token['expires_in'] / 60
        )
        expires_in = self.token['create_at'] + time_to_token_expires
        return expires_in
    
    
    def access_token_is_valid(self)->bool:
        """
        This function validates whether the provided access token is valid or not.

        Args:
            access_token (dict): A dictionary representing the access token.

        Returns:
            bool: True if the access token is valid, False otherwise.
        """
        expires_in = self.access_token_expiration_data()
        if datetime.now() > expires_in:
            return False
        else:
            return True
    
    def refresh_token(self):
        self.token = self.create_access_token()
        

    async def async_fetch_information(self, session, external_key):
        """

        This asynchronous function retrieves custom data views information using the provided a
        iohttp session and external key.

        Args:
            session (aiohttp.ClientSession): An aiohttp session for performing asynchronous requests.
            external_key (str): The external key to retrieve custom information.

        Raises:
            ValueError: Error fetching data views information: Not authorized after 2 attempts.
            ValueError: Error during request (get information): Aiohttp client error.
            ValueError: Error during request (get information): Another unhandled exception.

        Returns:
            dict: A dictionary containing information retrieved from the data view.
        """
        infos = {}
        endpoint = f"data/v1/customobjectdata/key/{external_key}/rowset"
        url = self.REST_base_url + endpoint
        headers = {
            "Authorization": "Bearer " + self.token['access_token']
        }

        try:
            retry = 0
            while retry < 2:
                async with session.get(url, headers=headers) as response:
                    if response.status == 401:
                        self.refresh_token()
                        retry += 1
                        continue
                    elif response.status != 200:
                        raise ValueError('Error(Fetch data views information: Error not mapped yet)')

                    response_json = await response.json()
                    infos['external_key'] = external_key
                    infos['requestToken'] = response_json['requestToken']
                    infos['pageSize'] = response_json['pageSize']
                    infos['count'] = response_json['count']
                    infos['number_pages'] = math.ceil(
                        infos['count'] / response_json['pageSize']
                    )
                    print('----->', infos)
                    return infos

            raise ValueError('Error(Fetch data views information: Not Authorized)')

        except aiohttp.ClientError as e:
            raise ValueError('Error during request (get informations): {}'.format(str(e)))
        except Exception as e:
            return e

            
            
    async def async_get_data_views_informations(self,external_key,total_timeout=30):
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=total_timeout)) as session:
            return await self.async_fetch_information(
                session=session,
                external_key=external_key,
                )
    
    def get_data_views_informations(self,external_key:str,total_timeout:int=30):
        return asyncio.run(
            self.async_get_data_views_informations(external_key,total_timeout)
        )


if __name__ == '__main__':
    sfmc = DataViewsCollection(
        authentication_base_url=os.environ.get("authentication_base_url"),
        rest_base_url=os.environ.get("rest_base_url"),
        client_id=os.environ.get("client_id"),
        cliente_secret=os.environ.get("cliente_secret"),
    )
    
    teste_lp_informations = sfmc.get_data_views_informations('teste_lp')
    pass
