from wcf.xml2records import XMLParser
from wcf.records import dump_records
from wcf.records import Record, print_records
import io

def binarytoxml(binaryxml):
    fp = io.BytesIO(binaryxml)
    records = Record.parse(fp)
    return print_records(records)

def xmltobinary(dataxml):
    r = XMLParser.parse(dataxml)
    data = dump_records(r)
    return data
