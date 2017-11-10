import xml.etree.ElementTree as ElementTree
import base64
import os
from openvas_lib import VulnscanManager, VulnscanException
from threading import Semaphore
from functools import partial
from openvas_lib import VulnscanManager, VulnscanException


def my_print_status(i):
    print(str(i))

def write_report(manager, report_id, ip):
	result_dir = os.path.dirname(os.path.abspath(__file__)) + "/results/"
	if not os.path.exists(result_dir):
	    os.makedirs(result_dir)
	try:	
		#print "report_id=" , report_id
		report = manager.get_report_html(report_id)
		print "type=", type(report)

		#print etree.tostring(report)
	except Exception as e:
		print(e)
		return
	else:
		fout = open(result_dir  + ip + ".html", "wb")
                fout.write(ElementTree.tostring(report, encoding='utf-8', method='html'))
                fout.close()

	try:
		report = manager.get_report_xml(report_id)
	except Exception as e:
		print(e)
		return
	else:
		fout = open(result_dir  + ip + ".xml", "wb")
		fout.write(ElementTree.tostring(report, encoding='utf-8', method='xml'))
		fout.close()


def main():
    try:
	TARGET_IP = "127.0.0.1"
	OPENVAS_HOST = "127.0.0.1"
	USER = "admin"
	PASSWORD = "12d419cb-8820-4b6f-aefc-79bfece6901c"
	PORT = 9390
	TIMEOUT = None
	#profile = "empty"
	profile = "Full and fast"
	manager = VulnscanManager(OPENVAS_HOST, USER, PASSWORD)
	
	sem = Semaphore(0)

	# Launch
	scan_id, target_id = manager.launch_scan(target= TARGET_IP ,profile=profile ,callback_end = partial(lambda x: x.release(), sem),callback_progress = my_print_status)

	print "scan_id=%s , target_id=%s " % ( scan_id, target_id  )
	
	# Wait
	sem.acquire()

	# Finished scan
	print("finished")
	
	report_id = manager.get_report_id(scan_id)
	write_report(manager, report_id, TARGET_IP )
	manager.delete_scan(scan_id)
	manager.delete_target(target_id)
	
    except VulnscanException, e:
       print "Error:"
       print e


main()
