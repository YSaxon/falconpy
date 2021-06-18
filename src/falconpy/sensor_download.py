"""
 _______                        __ _______ __        __ __
|   _   .----.-----.--.--.--.--|  |   _   |  |_.----|__|  |--.-----.
|.  1___|   _|  _  |  |  |  |  _  |   1___|   _|   _|  |    <|  -__|
|.  |___|__| |_____|________|_____|____   |____|__| |__|__|__|_____|
|:  1   |                         |:  1   |
|::.. . |   CROWDSTRIKE FALCON    |::.. . |    FalconPy
`-------'                         `-------'

OAuth2 API - Customer SDK

sensor_download - Falcon Sensor Download API Interface Class

This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or
distribute this software, either in source code form or as a compiled
binary, for any purpose, commercial or non-commercial, and by any
means.

In jurisdictions that recognize copyright laws, the author or authors
of this software dedicate any and all copyright interest in the
software to the public domain. We make this dedication for the benefit
of the public at large and to the detriment of our heirs and
successors. We intend this dedication to be an overt act of
relinquishment in perpetuity of all present and future rights to this
software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

For more information, please refer to <https://unlicense.org>
"""
from datetime import datetime
import os
from typing_extensions import Literal

from pydantic.main import BaseModel
from pydantic.tools import parse_obj_as
from ._util import service_request, parse_id_list, generate_ok_result
from ._service_class import ServiceClass

class SensorInstaller(BaseModel):
    name:str
    description:str
    platform: Literal['linux','windows','mac']
    os: Literal['Amazon Linux', 'Debian', 'RHEL/CentOS/Oracle', 'SLES', 'Ubuntu', 'Windows', 'macOS','']
        #blank values = Falcon SIEM Connector so should probably be filtered out of most results searches
    os_version: str
        # macOS {''}
        # RHEL/CentOS/Oracle {'8', '7', '6'}
        # Amazon Linux {'1', '2', '2 - arm64'}
        # Windows {''}
        # SLES {'15', '11', '12'}
        # Debian {'9/10', '9'}
        # Ubuntu {'16/18/20', '14/16/18/20'}
    sha256: str #these are used as the key for actually downloading
    release_date: datetime
    version:str #usually an entry for every valid os,os_version combo for each version
    file_size:int
    file_type: Literal['rpm','deb','pkg','exe'] #relevant for auto-unpacking, these are mostly 1:1 with os
        # '' {'rpm', 'deb'} but those are Falcon SIEM Connector
        # macOS {'pkg'}
        # RHEL/CentOS/Oracle {'rpm'}
        # Amazon Linux {'rpm'}
        # Windows {'exe'}
        # SLES {'rpm'}
        # Debian {'deb'}
        # Ubuntu {'deb'}
    
    def as_query_filter(self):
        return '+'.join([
            f"{k}:'{v}'" for k,v in self.__fields__ if k is not None and v is not None
        ])
    
    

class Sensor_Download(ServiceClass):
    """The only requirement to instantiate an instance of this class
       is a valid token provided by the Falcon API SDK OAuth2 class.
    """
    
    
    def _validate(self,response:dict):#this should probably be higher up in class hierarchy anyway
        # check_for_errors_and_raise_error()
        # check_for_missing_resources_and_raise_error()
        return response['body']['resources']
    
    
    #@ friendly(GetCombinedSensorInstallersByQuery,'parameters',List[SensorInstaller])
    def list_sensor_installers(self: object, sort='release_date|desc',filter='*',offset=0,limit=100) -> list[SensorInstaller]:
        if limit > 500: raise ValueError('max for limit is 500, you can paginate with offset if neccesary')
        result=self.GetCombinedSensorInstallersByQuery(dict(sort=sort,filter=filter,offset=offset,limit=limit))
        resources=self.validate_and_get_resources(result)
        installers=parse_obj_as(list[SensorInstaller], resources)
        return installers
        #these should be decorators!

    
    
    def GetCombinedSensorInstallersByQuery(self: object, parameters: dict = None) -> dict:
        """
        Retrieve all metadata for installers from provided query
        """
        FULL_URL = self.base_url+'/sensors/combined/installers/v1'
        HEADERS = self.headers
        if parameters is None:
            parameters = {}
        PARAMS = parameters
        returned = service_request(caller=self,
                                   method="GET",
                                   endpoint=FULL_URL,
                                   params=PARAMS,
                                   headers=HEADERS,
                                   verify=self.ssl_verify
                                   )
        return returned

    def DownloadSensorInstallerById(self: object,
                                    parameters: dict,
                                    file_name: str = None,
                                    download_path: str = None
                                    ) -> object:
        """
        Download the sensor by the sha256 id, into the specified directory.
        The path will be created for the user if it does not already exist
        """
        FULL_URL = self.base_url+"/sensors/entities/download-installer/v1"
        HEADERS = self.headers
        PARAMS = parameters
        returned = service_request(caller=self,
                                   method="GET",
                                   endpoint=FULL_URL,
                                   headers=HEADERS,
                                   params=PARAMS,
                                   verify=self.ssl_verify
                                   )
        if file_name and download_path and isinstance(returned, bytes):
            os.makedirs(download_path, exist_ok=True)
            # write the newly downloaded sensor into the aforementioned directory with provided file name
            with open(os.path.join(download_path, file_name), "wb") as sensor:
                sensor.write(returned)
            returned = generate_ok_result(message="Download successful")
        return returned

    def GetSensorInstallersEntities(self: object, ids: list or str) -> object:
        """
        For a given list of SHA256's, retrieve the metadata for each installer
        such as the release_date and version among other fields
        """
        ID_LIST = str(parse_id_list(ids)).replace(",", "&ids=")
        FULL_URL = self.base_url+'/sensors/entities/installers/v1?ids={}'.format(ID_LIST)
        HEADERS = self.headers
        returned = service_request(caller=self,
                                   method="GET",
                                   endpoint=FULL_URL,
                                   headers=HEADERS,
                                   verify=self.ssl_verify
                                   )
        return returned

    def GetSensorInstallersCCIDByQuery(self: object) -> dict:
        """
        Retrieve the CID for the current oauth environment
        """
        FULL_URL = self.base_url+'/sensors/queries/installers/ccid/v1'
        HEADERS = self.headers
        returned = service_request(caller=self,
                                   method="GET",
                                   endpoint=FULL_URL,
                                   headers=HEADERS,
                                   verify=self.ssl_verify
                                   )
        return returned

    def GetSensorInstallersByQuery(self: object, parameters: dict = None) -> dict:
        """
        Retrieve a list of SHA256 for installers based on the filter
        """
        FULL_URL = self.base_url+'/sensors/queries/installers/v1'
        HEADERS = self.headers
        if parameters is None:
            parameters = {}
        PARAMS = parameters
        returned = service_request(caller=self,
                                   method="GET",
                                   endpoint=FULL_URL,
                                   params=PARAMS,
                                   headers=HEADERS,
                                   verify=self.ssl_verify
                                   )
        return returned
