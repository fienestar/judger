from django.shortcuts import render, redirect
from .forms import SubmissionForm
from django.http import HttpResponseRedirect, JsonResponse
import pika
import myproject.settings as settings

def submit_code(request):
    if request.method == 'POST':
        form = SubmissionForm(request.POST)
        if form.is_valid():
            form.save()
            return JsonResponse({'success': True, 'message': '코드가 성공적으로 제출되었습니다!'})
    else:
        form = SubmissionForm()
    return render(request, 'submissions/submit_code.html', {'form': form})

def success(request):
    return render(request, 'submissions/success.html')

def redirect_to_submit(request):
    return HttpResponseRedirect('/submit/')

def send_to_rabbitmq(code, language):
    connection = pika.BlockingConnection(
        pika.ConnectionParameters(host=settings.RABBITMQ_HOST,
            port=5672,
            credentials=pika.PlainCredentials('rabbitmq username ss', 'rabbitmq password ss')
        )
    )
    channel = connection.channel()

    channel.queue_declare(queue=settings.RABBITMQ_QUEUE_NAME)

    message = {
        'code': code,
        'language': language,
    }
    channel.basic_publish(
        exchange='',
        routing_key=settings.RABBITMQ_QUEUE_NAME,
        body=str(message)
    )
    connection.close()

def send_code(request):
    if request.method == 'POST':
        form = SubmissionForm(request.POST)
        if form.is_valid():
            form.save()

            code = form.cleaned_data['code']
            language = form.cleaned_data['language']

            send_to_rabbitmq(code=code, language=language)

            return JsonResponse({'success': True, 'message': '코드가 성공적으로 제출되었습니다!'})
    else:
        form = SubmissionForm()
    return render(request, 'submit_code.html', {'form': form})