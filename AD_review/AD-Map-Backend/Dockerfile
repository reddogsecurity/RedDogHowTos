# Use the official .NET 8 runtime as base image
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
WORKDIR /app
EXPOSE 5000
EXPOSE 7001

# Use the SDK image for building
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY ["AD-Map-Backend.csproj", "."]
RUN dotnet restore "AD-Map-Backend.csproj"
COPY . .
WORKDIR "/src"
RUN dotnet build "AD-Map-Backend.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "AD-Map-Backend.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .

# Create data directory
RUN mkdir -p /app/data

# Create certificates directory
RUN mkdir -p /app/certs

# Set environment variables
ENV ASPNETCORE_ENVIRONMENT=Production
ENV ASPNETCORE_URLS=https://+:7001;http://+:5000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:5000/health || exit 1

ENTRYPOINT ["dotnet", "AD-Map-Backend.dll"]
