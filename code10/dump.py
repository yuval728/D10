# class UserView(APIView):
#     # permission_classes = (permissions.IsAuthenticated)
#     def get(self, request, pk=None):
#         if pk:
#             user = get_object_or_404(User.objects.all(), pk=pk)
#             serializer = UserSerializer(user, context={'request': request})
#             return Response(serializer.data, status=status.HTTP_200_OK)
        
#         users = User.objects.all()
#         serializer = UserSerializer(users, many=True, context={'request': request})
#         return Response(serializer.data, status=status.HTTP_200_OK)
    
#     def post(self, request):
#         serializer = UserSerializer(data=request.data, context={'request': request})
#         if serializer.is_valid():
#             serializer.save()
#             print(serializer.data)
#             return Response(serializer.data,status=status.HTTP_201_CREATED)
        
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

#     def put(self, request):
#         id=request.data.get('id')
#         user = User.objects.get(id=id)
#         serializer = UserSerializer(user, data=request.data, context={'request': request})
#         if serializer.is_valid():
#             serializer.save()
#             return Response(serializer.data,status=status.HTTP_202_ACCEPTED)
        
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
#     def delete(self,request, pk):
#         user = User.objects.get(id=pk)
#         user.delete()
#         return Response({'message': 'User deleted successfully'}, status=status.HTTP_204_NO_CONTENT)
    


# @api_view(['GET', 'POST'])
# @permission_classes([permissions.AllowAny])
# async def user_list(request):
#     if request.method == 'GET':
#         users = User.objects.all()
#         serializer = UserSerializer(users, many=True, context={'request': request})
#         return Response(serializer.data, status=status.HTTP_200_OK)
    
#     elif request.method == 'POST':
#         serializer = UserSerializer(data=request.data, context={'request': request})
#         if serializer.is_valid():
#             serializer.save()
#             return Response(serializer.data,status=status.HTTP_201_CREATED)
        
#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)