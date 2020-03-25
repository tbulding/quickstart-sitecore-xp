#  Copyright 2016 Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
#  This file is licensed to you under the AWS Customer Agreement (the "License").
#  You may not use this file except in compliance with the License.
#  A copy of the License is located at http://aws.amazon.com/agreement/ .
#  This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express or implied.
#  See the License for the specific language governing permissions and limitations under the License.

from crhelper import CfnResource
import boto3
from botocore.exceptions import ClientError

# Clients
ssm = boto3.client('ssm')
r53 = boto3.client('route53')
helper = CfnResource()

def get_param_value(parameter_name):
    try:
        response = ssm.get_parameter(
            Name=parameter_name
        )
        return response['Parameter']
    except ClientError as e:
        if e.response['Error']['Code'] == 'ParameterNotFound':
            response = "ParameterNotFound : "+parameter_name
            return response
        else:
            return e.response['Error']
            
def get_r53_record(zone_id, record_name, record_type):
    response = r53.list_resource_record_sets(
        HostedZoneId=zone_id,
        StartRecordName=record_name,
        StartRecordType=record_type
    )
    return response

def del_r53_record(zone_id, record_name, record_type, ttl, record_value):
    response = r53.change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={
            'Changes': [
                {
                    'Action': 'DELETE',
                    'ResourceRecordSet': {
                        'Name': record_name,
                        'Type': record_type,
                        'TTL': ttl,
                        'ResourceRecords': [
                            {
                                'Value': record_value
                            },
                        ]
                    }
                }
            ]
        }
    )
    return response

def solr_r53(hosted_zone, int_dns_param):
    internal_domain = get_param_value(int_dns_param)

    record_name = 'solrdev.'+ internal_domain['Value']
    record_type = 'CNAME'
    ttl = 300

    get_record = get_r53_record(hosted_zone, record_name, record_type)
    record_value = get_record['ResourceRecordSets'][0]['ResourceRecords'][0]['Value']
    print('Deleting ' + record_name + ' (' + record_value + ')')
    delete_record = del_r53_record(hosted_zone, record_name, record_type, ttl, record_value)
        
    return delete_record

def handler(event, context):
    helper(event, context)

@helper.create
@helper.update
def no_op(_, __):
    pass

@helper.delete
def remove_resources(event, context):
    scqs_prefix = event['ResourceProperties']['SCQSPrefix']
    scqs_string = event['ResourceProperties']['SCQSRandomString']
    R53_hosted_zone = event['ResourceProperties']['R53HostedZoneID'] # The R53 Hosted Zone
    ssm_internal_dns = '/' + scqs_prefix + '/service/internaldns'

    clean_r53 = solr_r53(R53_hosted_zone, ssm_internal_dns)
    print(clean_r53)